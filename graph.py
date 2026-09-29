import bisect
import os

from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict, Any
from typing_extensions import Annotated
import operator
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from vectorstore import search as vector_search

MODEL = os.getenv("REVIEW_MODEL", "llama3.2")
# A normal review is 3-4 findings, a few hundred tokens. What hits this cap is a
# repetition loop (37-45 findings seen), which no cap makes valid - raising it
# only makes a runaway burn longer before it fails.
MAX_OUTPUT_TOKENS = 1536
REQUEST_TIMEOUT_S = 600
# Retrieval runs only for diffs at least this long (characters of sanitised code).
# Below it, the eval measured no detection benefit across two runs, and 14% of
# findings copying the retrieved examples' vulnerability names against 0% without.
# Whether it helps on large diffs is untested; the default sits ~10x above the
# largest diff the eval covers. 0 means always retrieve, a huge value means never.
RETRIEVAL_MIN_CHARS = int(os.getenv("RETRIEVAL_MIN_CHARS", "20000"))


def _reviewer(schema):

    llm = ChatOllama(
        model=MODEL,
        temperature=0,
        num_predict=MAX_OUTPUT_TOKENS,
        client_kwargs={"timeout": REQUEST_TIMEOUT_S},
    )
    return llm.with_structured_output(schema)

class GraphState(TypedDict):

    pr_metadata: Dict[str, Any]
    raw_diff: str
    sanitized_diff: str
    pr_context: Dict[str, Any]
    retrieved_examples: List[Dict[str, Any]]

    exclude_snippets: List[str]
    
    static_findings: Annotated[List[Dict[str, Any]], operator.add]
    security_findings: Annotated[List[Dict[str, Any]], operator.add]
    # Findings dropped because their quoted evidence is not in the diff.
    unverified_findings: List[Dict[str, Any]]
    final_review: str

# PR context extracted from LLM
class PRContext(BaseModel):
    """
    Strict JSON schema enforcing the exact output the Router Agent must produce.
    """
    primary_language: str = Field(description="The primary programming language of the code snippet.")
    imported_libraries: List[str] = Field(description="A list of up to 3 core libraries or frameworks being used.")
    core_concept: str = Field(description="A two-word summary of the logic (e.g., 'SQL Query', 'File Upload').")

# To be retrieved from ChromaDB
class SecurityFinding(BaseModel):
    """
    Strict JSON schema enforcing the exact output the Security Finder agent must produce.
    """
    # Evidence first, so the model quotes the code before it makes a claim about it.
    # No line number: the model counts lines badly, so it is computed from the quote.
    evidence: str = Field(description="The exact line of code that contains the vulnerability, copied verbatim from the diff")
    description: str = Field(description="Description of vulnerability")
    severity: str = Field(description="How severe is the vulnerability: CRITICAL, HIGH, MEDIUM, or LOW")
    fix: str = Field(description="Suggested fix for the vulnerability")

class SecurityFindings(BaseModel):
    """Wrapper to get a list of security findings from the LLM."""
    findings: List[SecurityFinding] = Field(description="List of security vulnerabilities found in the code")

class StaticFinding(BaseModel):
    """
    Schema for code quality / best-practice issues.
    """
    category: str = Field(description="Category of issue: 'style', 'performance', 'maintainability', 'error-handling', or 'best-practice'")
    line_number: int = Field(description="Approximate line number of the issue")
    description: str = Field(description="Description of the code quality issue")
    suggestion: str = Field(description="Suggested improvement")

class StaticFindings(BaseModel):
    """Wrapper to get a list of static analysis findings from the LLM."""
    findings: List[StaticFinding] = Field(description="List of code quality issues found in the code")


# Node to remove unnecessary git headers/symbols and call LLM to get context for code snippet
def get_context(state: GraphState) -> Dict[str, Any]:

    print("=== [NODE 1] TRIAGE ROUTER ===")
    raw_diff = state.get("raw_diff", "")
    
    sanitized_lines = []
    for line in raw_diff.split('\n'):
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        if line.startswith('+'):
            sanitized_lines.append(line[1:]) 
        elif line.startswith(' '):
            sanitized_lines.append(line[1:])
            
    sanitized_diff = "\n".join(sanitized_lines)
 
    structured_llm = _reviewer(PRContext)
    
    system_prompt = """You are a highly analytical code extraction agent. 
    Read the provided code snippet. Your ONLY job is to identify the primary programming language, 
    list the core imported libraries (max 3), and summarize the underlying technical concept in two words.
    Do NOT look for bugs or vulnerabilities."""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Analyze this code:\n\n{code}")
    ])
    
    chain = prompt | structured_llm
    extraction_result = chain.invoke({"code": sanitized_diff})
    
    print(f"  Language : {extraction_result.primary_language}")
    print(f"  Libraries: {extraction_result.imported_libraries}")
    print(f"  Concept  : {extraction_result.core_concept}")
    
    return {
        "sanitized_diff": sanitized_diff,
        "pr_context": extraction_result.model_dump()
    }

# Create semnatic query from PR Context and code then search ChromaDB
def retrieve_examples(state: GraphState) -> Dict[str, Any]:

    print("=== [NODE 2] RETRIEVE EXAMPLES (Vector DB) ===")
    pr_context = state.get("pr_context", {})
    sanitized_diff = state.get("sanitized_diff", "")

    language = pr_context.get("primary_language", "")
    libraries = ", ".join(pr_context.get("imported_libraries", []))
    concept = pr_context.get("core_concept", "")

    code_snippet = sanitized_diff[:500]  
    search_query = (
        f"Language: {language}. Libraries: {libraries}. Concept: {concept}. "
        f"Code:\n{code_snippet}"
    )

    print(f"  Query: {language} | {libraries} | {concept}")


    results = vector_search(
        query=search_query,
        n_results=3,
        exclude_containing=state.get("exclude_snippets") or None,
    )

    retrieved = []
    for i, r in enumerate(results):
        print(f"  [{i+1}] {r['id']} (distance: {r['distance']:.4f})")
        retrieved.append({
            "id": r["id"],
            "document": r["document"],
            "metadata": r["metadata"],
            "distance": r["distance"],
        })

    print(f"  Retrieved {len(retrieved)} examples via vector similarity")
    return {"retrieved_examples": retrieved}

# Analyze code and retrieved examples, return description of vulnerabilities if any
def _squash(text: str) -> str:
    # Whitespace and quote style are what a model changes when it copies code - and
    # it often rejoins a statement the source splits across lines, so whitespace is
    # removed entirely rather than collapsed.
    return "".join(text.replace('"', "'").split())


def locate_evidence(evidence: str, code: str) -> int | None:
    """1-based line where the quoted `evidence` starts in `code`, else None."""
    joined, starts = "", []
    for line in code.splitlines():
        starts.append(len(joined))
        joined += _squash(line)

    # The whole quote first, then line by line: a quote can carry fences or a
    # stray line of prose around the real code.
    candidates = [evidence] + evidence.splitlines()
    for quoted in candidates:
        quoted = _squash("\n".join(l.strip().strip("`").lstrip("+- ") for l in quoted.splitlines()))
        if len(quoted) < 8:  # fences, language tags, lone braces: matches anything
            continue
        position = joined.find(quoted)
        if position >= 0:
            return bisect.bisect_right(starts, position)
    return None


def verify_findings(findings: List[Dict[str, Any]], code: str) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(kept, dropped): a finding is kept only if its evidence is really in the code."""
    kept, dropped = [], []
    for finding in findings:
        line = locate_evidence(finding.get("evidence", ""), code)
        if line is None:
            dropped.append(finding)
        else:
            kept.append({**finding, "line_number": line})
    return kept, dropped


def security_agent(state: GraphState) -> Dict[str, Any]:

    print("=== [NODE 3a] SECURITY AGENT ===")
    sanitized_diff = state.get("sanitized_diff", "")
    retrieved = state.get("retrieved_examples", [])

    examples_text = ""
    for i, ex in enumerate(retrieved, 1):
        doc_text = ex.get("document", "")
        if len(doc_text) > 2000:
            doc_text = doc_text[:2000] + "\n[...truncated...]"
        distance = ex.get("distance", "N/A")
        examples_text += f"\n--- Reference Example {i} (ID: {ex.get('id', 'N/A')}, similarity: {distance}) ---\n"
        examples_text += f"{doc_text}\n"

    structured_llm = _reviewer(SecurityFindings)

    system_prompt = """You are an expert application security engineer performing a code review.
Analyze the provided code diff for security vulnerabilities. Use the reference examples as guidance
for the types of vulnerabilities to look for and how to report them.

Focus on:
- Injection flaws (SQL, command, XSS)
- Authentication / authorization issues
- Hardcoded secrets or credentials
- Insecure cryptographic practices
- Data exposure risks
- Input validation gaps

For each vulnerability found, provide:
- evidence (the exact line of code that contains the flaw, copied verbatim from the diff)
- description (clear explanation of the risk)
- severity (CRITICAL / HIGH / MEDIUM / LOW)
- fix (concrete remediation step)

Report only vulnerabilities you can point to in a specific line of this diff. A finding
whose evidence is not in the diff is discarded.

If the code is secure, return an empty findings list."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "## Code Diff to Review:\n```\n{diff}\n```\n\n## Reference Vulnerability Examples:\n{examples}")
    ])

    chain = prompt | structured_llm
    result = chain.invoke({"diff": sanitized_diff, "examples": examples_text})

    findings, unverified = verify_findings([f.model_dump() for f in result.findings], sanitized_diff)
    print(f"  Found {len(findings)} security issue(s), dropped {len(unverified)} without evidence in the diff")
    for f in findings:
        print(f"    [{f['severity']}] Line {f['line_number']}: {f['description'][:80]}")

    return {"security_findings": findings, "unverified_findings": unverified}

# Analyze code for efficinecy/best-practices issues
def static_analysis_agent(state: GraphState) -> Dict[str, Any]:

    print("=== [NODE 3b] STATIC ANALYSIS AGENT ===")
    sanitized_diff = state.get("sanitized_diff", "")
    pr_context = state.get("pr_context", {})

    structured_llm = _reviewer(StaticFindings)

    system_prompt = """You are a senior software engineer performing a code quality review.
The code is written in {language}. Analyze the diff for NON-SECURITY issues only.

Focus on:
- Code style and readability
- Error handling gaps (missing try/except, unchecked return values)
- Performance concerns (unnecessary loops, resource leaks)
- Maintainability (magic numbers, missing docstrings, unclear naming)
- Best practices for the detected language and frameworks

For each issue, provide:
- category (style / performance / maintainability / error-handling / best-practice)
- line_number (approximate)
- description (what the issue is)
- suggestion (how to improve it)

If the code is clean, return an empty findings list."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "## Code Diff:\n```\n{diff}\n```\n\nLanguage: {language}\nLibraries: {libraries}\nConcept: {concept}")
    ])

    chain = prompt | structured_llm
    result = chain.invoke({
        "diff": sanitized_diff,
        "language": pr_context.get("primary_language", "unknown"),
        "libraries": ", ".join(pr_context.get("imported_libraries", [])),
        "concept": pr_context.get("core_concept", "unknown")
    })

    findings = [f.model_dump() for f in result.findings]
    print(f"  Found {len(findings)} code quality issue(s)")
    for f in findings:
        print(f"    [{f['category']}] Line {f['line_number']}: {f['description'][:80]}")

    return {"static_findings": findings}

# Return issues and suggestions if any
def generate_final_review(state: GraphState) -> Dict[str, Any]:

    print("=== [NODE 4] GENERATE FINAL REVIEW ===")
    pr_context = state.get("pr_context", {})
    security_findings = state.get("security_findings", [])
    static_findings = state.get("static_findings", [])

    total = len(security_findings) + len(static_findings)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    critical_count = sum(1 for f in security_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in security_findings if f.get("severity") == "HIGH")

    if critical_count > 0:
        verdict = "CHANGES REQUESTED — Critical vulnerabilities found"
    elif high_count > 0:
        verdict = "CHANGES REQUESTED — High-severity issues found"
    elif total > 0:
        verdict = "APPROVED WITH SUGGESTIONS"
    else:
        verdict = "APPROVED — No issues found"

    # GitHub-flavoured Markdown, because the report is posted as a pull request
    # comment: there, lines separated by a single newline merge into one paragraph
    # unless they are list items.
    lines = [
        f"**Verdict:** {verdict}",
        "",
        f"{pr_context.get('primary_language', 'Unknown language')} · "
        f"{pr_context.get('core_concept', 'n/a')} · "
        f"{len(security_findings)} security, {len(static_findings)} code quality",
        "",
    ]

    if security_findings:
        lines += ["#### Security findings", ""]
        sorted_sec = sorted(security_findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))
        for i, finding in enumerate(sorted_sec, 1):
            lines.append(f"{i}. **{finding.get('severity', 'UNKNOWN')}** (line {finding.get('line_number', '?')}): "
                         f"{finding.get('description', 'N/A')}")
            lines.append(f"   - **Fix:** {finding.get('fix', 'N/A')}")
        lines.append("")

    if static_findings:
        lines += ["#### Code quality findings", ""]
        for i, finding in enumerate(static_findings, 1):
            lines.append(f"{i}. **{finding.get('category', 'general')}** (line {finding.get('line_number', '?')}): "
                         f"{finding.get('description', 'N/A')}")
            lines.append(f"   - **Suggestion:** {finding.get('suggestion', 'N/A')}")
        lines.append("")

    if total == 0:
        lines.append("No security or code quality issues detected.")

    review = "\n".join(lines)
    print(f"  Report generated ({len(review)} chars)")
    print(f"  Verdict: {verdict}")

    return {"final_review": review}


def route_after_triage(state: GraphState) -> str | List[str]:
    # ponytail: the retrieval query reads only the diff's first 500 characters, which
    # on the large diffs it now serves can miss the vulnerable part. Query per chunk
    # if a test shows retrieval earns its place there.
    if len(state.get("sanitized_diff", "")) >= RETRIEVAL_MIN_CHARS:
        return "retrieve_examples"
    return ["security_agent", "static_analysis_agent"]


def build_review_graph() -> StateGraph:

    graph = StateGraph(GraphState)

    graph.add_node("triage_router", get_context)
    graph.add_node("retrieve_examples", retrieve_examples)
    graph.add_node("security_agent", security_agent)
    graph.add_node("static_analysis_agent", static_analysis_agent)
    graph.add_node("generate_final_review", generate_final_review)

    graph.set_entry_point("triage_router")

    # Large diffs go through retrieval; everything else straight to the agents.
    # The eval calls the nodes directly, so its RAG ablation is unaffected.
    graph.add_conditional_edges("triage_router", route_after_triage,
                                ["retrieve_examples", "security_agent", "static_analysis_agent"])

    graph.add_edge("retrieve_examples", "security_agent")
    graph.add_edge("retrieve_examples", "static_analysis_agent")

    graph.add_edge("security_agent", "generate_final_review")
    graph.add_edge("static_analysis_agent", "generate_final_review")

    graph.add_edge("generate_final_review", END)

    return graph.compile()


review_graph = build_review_graph()


def run_review(raw_diff: str, pr_metadata: Dict[str, Any]) -> str:

    initial_state: GraphState = {
        "pr_metadata": pr_metadata,
        "raw_diff": raw_diff,
        "sanitized_diff": "",
        "pr_context": {},
        "retrieved_examples": [],
        "exclude_snippets": [],
        "static_findings": [],
        "security_findings": [],
        "unverified_findings": [],
        "final_review": ""
    }

    final_state = review_graph.invoke(initial_state)
    return final_state["final_review"]

if __name__ == "__main__":
    # Dummy payload for testing
    dummy_webhook_payload = {
        "pr_metadata": {
            "repository": "auth-service",
            "pr_number": 104,
            "author": "dev-user"
        },
        "raw_diff": """diff --git a/database.py b/database.py
@@ -10,4 +10,8 @@
 import sqlite3
 
 def get_user(username):
-    # TODO: implement
+    conn = sqlite3.connect('users.db')
+    cursor = conn.cursor()
+    # Vulnerable implementation added for testing
+    query = f"SELECT * FROM users WHERE username = '{username}'"
+    cursor.execute(query)
+    return cursor.fetchone()
"""
    }

    print("=" * 60)
    print("  CODE REVIEW AGENT — Test Run")
    print("=" * 60)

    report = run_review(
        raw_diff=dummy_webhook_payload["raw_diff"],
        pr_metadata=dummy_webhook_payload["pr_metadata"]
    )

    print("=" * 60)
    print("  FINAL REVIEW REPORT")
    print("=" * 60)
    print(report)