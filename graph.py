from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict, Any
from typing_extensions import Annotated
import operator
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from vectorstore import search as vector_search

# Declare graph state schema
class GraphState(TypedDict):

    pr_metadata: Dict[str, Any]
    raw_diff: str
    sanitized_diff: str
    pr_context: Dict[str, Any]
    retrieved_examples: List[Dict[str, Any]]
    
    # Annotated with operator.add so parallel nodes append rather than overwrite
    static_findings: Annotated[List[Dict[str, Any]], operator.add]
    security_findings: Annotated[List[Dict[str, Any]], operator.add]
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
    severity: str = Field(description="How severe is the vulnerability: CRITICAL, HIGH, MEDIUM, or LOW")
    line_number: int = Field(description="Number of the line where the vulnerability is")
    description: str = Field(description="Description of vulnerability")
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

    print("\n=== [NODE 1] TRIAGE ROUTER ===")
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
 
    llm = ChatOllama(model="llama3.2", temperature=0)
    structured_llm = llm.with_structured_output(PRContext)
    
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

    print("\n=== [NODE 2] RETRIEVE EXAMPLES (Vector DB) ===")
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


    results = vector_search(query=search_query, n_results=3)

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
def security_agent(state: GraphState) -> Dict[str, Any]:

    print("\n=== [NODE 3a] SECURITY AGENT ===")
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

    llm = ChatOllama(model="llama3.2", temperature=0)
    structured_llm = llm.with_structured_output(SecurityFindings)

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
- severity (CRITICAL / HIGH / MEDIUM / LOW)
- line_number (approximate line in the diff)
- description (clear explanation of the risk)
- fix (concrete remediation step)

If the code is secure, return an empty findings list."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "## Code Diff to Review:\n```\n{diff}\n```\n\n## Reference Vulnerability Examples:\n{examples}")
    ])

    chain = prompt | structured_llm
    result = chain.invoke({"diff": sanitized_diff, "examples": examples_text})

    findings = [f.model_dump() for f in result.findings]
    print(f"  Found {len(findings)} security issue(s)")
    for f in findings:
        print(f"    [{f['severity']}] Line {f['line_number']}: {f['description'][:80]}")

    return {"security_findings": findings}

# Analyze code for efficinecy/best-practices issues
def static_analysis_agent(state: GraphState) -> Dict[str, Any]:

    print("\n=== [NODE 3b] STATIC ANALYSIS AGENT ===")
    sanitized_diff = state.get("sanitized_diff", "")
    pr_context = state.get("pr_context", {})

    llm = ChatOllama(model="llama3.2", temperature=0)
    structured_llm = llm.with_structured_output(StaticFindings)

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

    print("\n=== [NODE 4] GENERATE FINAL REVIEW ===")
    pr_metadata = state.get("pr_metadata", {})
    pr_context = state.get("pr_context", {})
    security_findings = state.get("security_findings", [])
    static_findings = state.get("static_findings", [])

    lines = []
    lines.append("AI Code Review Report\n")

    lines.append("PR Metadata")
    lines.append(f"-Repository: {pr_metadata.get('repository', 'N/A')}")
    lines.append(f"-PR Number: {pr_metadata.get('pr_number', 'N/A')}")
    lines.append(f"-Author: {pr_metadata.get('author', pr_metadata.get('authot_name', 'N/A'))}")
    lines.append(f"-Commit: `{pr_metadata.get('commit_hash', 'N/A')}`")
    lines.append(f"-Language: {pr_context.get('primary_language', 'N/A')}")
    lines.append(f"-Concept: {pr_context.get('core_concept', 'N/A')}")
    lines.append("")

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

    lines.append(f"Verdict: {verdict}")
    lines.append(f"Total Findings: {total}")
    lines.append(f"Security: {len(security_findings)}")
    lines.append(f"Code Quality: {len(static_findings)}")
    lines.append("")

    if security_findings:
        lines.append("## Security Findings\n")
        sorted_sec = sorted(security_findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))
        for i, finding in enumerate(sorted_sec, 1):
            sev = finding.get("severity", "UNKNOWN")
            severity_labels = ["Critical", "High", "Medium", "Low", "Unknown"]
            icon = severity_labels[severity_order.get(sev, 4)]
            lines.append(f"{icon} {i}. [{sev}] {finding.get('description', 'N/A')}")
            lines.append(f"-Line: {finding.get('line_number', '?')}")
            lines.append(f"-Fix: {finding.get('fix', 'N/A')}")
            lines.append("")
    
    
    if static_findings:
        lines.append("Code Quality Findings\n")
        categories = ["style", "performance", "maintainability", "error-handling", "best-practice"]
        for i, finding in enumerate(static_findings, 1):
            cat = finding.get("category", "general")
            lines.append(f"{categories.index(cat) if cat in categories else 'General'} {i}. [{cat}] {finding.get('description', 'N/A')}")
            lines.append(f"-Line: {finding.get('line_number', '?')}")
            lines.append(f"-Suggestion: {finding.get('suggestion', 'N/A')}")
            lines.append("")

    if total == 0:
        lines.append("No security or code quality issues detected")

    lines.append("---")
    lines.append("Report generated by AI Code Review Agent (LangGraph + Ollama)")

    review = "\n".join(lines)
    print(f"  Report generated ({len(review)} chars)")
    print(f"  Verdict: {verdict}")

    return {"final_review": review}


def build_review_graph() -> StateGraph:

    graph = StateGraph(GraphState)

    graph.add_node("triage_router", get_context)
    graph.add_node("retrieve_examples", retrieve_examples)
    graph.add_node("security_agent", security_agent)
    graph.add_node("static_analysis_agent", static_analysis_agent)
    graph.add_node("generate_final_review", generate_final_review)

    graph.set_entry_point("triage_router")

    graph.add_edge("triage_router", "retrieve_examples")

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
        "static_findings": [],
        "security_findings": [],
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

    print("\n" + "=" * 60)
    print("  FINAL REVIEW REPORT")
    print("=" * 60)
    print(report)