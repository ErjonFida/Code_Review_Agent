# AI Code Review Agent

An **automated, multi-agent code review system** built with [LangGraph](https://langchain-ai.github.io/langgraph/), [Ollama](https://ollama.com/) (Llama 3.2), and [ChromaDB](https://www.trychroma.com/). The agent listens for GitHub `push` events via a webhook, analyses every changed file in each commit, and produces a structured Markdown review report covering **security vulnerabilities** and **code quality** issues.

`evals/`: a held-out suite of 40 expert-labelled cases
that reports what the reviewer actually catches - including the finding that
retrieval did not measurably improve detection. See [Evaluation](#evaluation).

---

## Schema

The system follows a **Retrieval-Augmented Generation (RAG)** pattern wired together as a LangGraph state machine. A single shared `GraphState` flows through four sequential/parallel nodes:

```
GitHub Push Event
       │
       ▼
┌──────────────┐
│  Flask App   │  ← receives webhook, fetches diffs via GitHub API
│  (app.py)    │
└──────┬───────┘
       │  raw diff + metadata
       ▼
┌──────────────────────────────────────────────────────────────┐
│                    LangGraph Pipeline                        │
│                                                              │
│  ┌────────────────┐    ┌─────────────────────┐               │
│  │ 1. Context     │──▶│ 2. Retrieve         │               │
│  └────────────────┘    |    Examples (RAG)   │               │
│                        └──────────┬──────────┘               │
│                           ┌──────┴──────┐                    │
│                           │             │                    │
│                     ┌─────▼─────┐ ┌─────▼──────────┐         │
│                     │ 3a.       │ │ 3b. Static     │         │
│                     │ Security  │ │ Analysis       │         │
│                     │ Agent     │ │ Agent          │         │
│                     └─────┬─────┘ └─────┬──────────┘         │
│                           │             │                    │
│                           └──────┬──────┘                    │
│                           ┌──────▼──────┐                    │
│                           │ 4. Generate │                    │
│                           │ Final Review│                    │
│                           └──────┬──────┘                    │
│                                  │                           │
│                                  ▼                           │
│                                 END                          │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
  Markdown Review Report (returned via JSON API)
```

### Overview

| Decision | Rationale |
|---|---|
| **LangGraph over a simple chain** | Fan-out lets the security and static agents be expressed independently, and `Annotated[List, operator.add]` merges their findings instead of overwriting. This does not currently reduce latency: both call one Ollama instance, which serialises them. |
| **Ollama (local LLM)** | Runs locally via `llama3.2`, avoids API costs and keeps code private — suitable for proprietary source. |
| **Structured output (Pydantic)** | Every LLM call uses `with_structured_output(PydanticModel)` to guarantee machine-parseable JSON.
| **ChromaDB (persistent vector store)** | A local, file-backed vector database stores 2,185 embedded vulnerability examples. Persistence avoids re-embedding on every restart (~30 min to build on CPU). |
| **nomic-embed-text embeddings** | A lightweight embedding model that runs locally via Ollama.
| **RAG for security guidance** | The pipeline retrieves the 3 most semantically similar vulnerability examples to ground the security agent in real patterns. Whether that helps is measured rather than assumed - on the current baseline it lowers false positives and detections alike, neither significantly. See [Evaluation](#evaluation). |
| **Diff sanitisation before analysis** | Git noise (`+++`, `---`, `@@` headers) is stripped in Node 1 so downstream agents only see meaningful code — improving embedding relevance and LLM focus. |

---

## Evaluation

**Method.** 40 cases are held out of the index and drawn from the same securecode
corpus. Each entry ships an expert-written vulnerable/secure code pair with CWE,
technique and severity labels, so every case is scored twice: the vulnerable
snippet must produce a finding naming the labelled vulnerability class, and its
secure counterpart must not. The suite drives the shipped nodes - `get_context`,
`retrieve_examples`, `security_agent` - so the numbers describe the agent the
webhook calls rather than a reimplementation of it.

**Baseline** - `llama3.2`, top-3 retrieval, 40 cases (39 scored, 1 parse failure).
Detection is scored by an LLM judge; the false-positive rate is still
substring-scored pending a re-run (see [Limitations](#limitations)):

| Metric | RAG | No-RAG |
|---|---:|---:|
| detection_rate | 0.795 | **0.825** |
| false_positive_rate | **0.359** | 0.500 |
| findings per vulnerable case | 3.18 | 4.31 |

**Retrieval has no measurable effect on detection.** Both arms run the same cases,
so the comparison is paired and only discordant cases carry information. McNemar's
exact test gives **p = 1.0** for detection (3 discordant: 1 RAG-only, 2 no-RAG-only)
and **p = 0.267** for false positives (13 discordant, substring-scored). The arms
differ by one case on recall.

What retrieval measurably does is make the reviewer quieter: fewer findings than
no-RAG in 21 of 39 cases, more in 6, a mean of 3.18 against 4.31, on secure code
as well as vulnerable. That buys fewer false positives and occasionally costs a
detection - both cases RAG lost returned **no findings at all**, not a wrong one.
An earlier reading that retrieval misdirects the model toward the retrieved
example's class rested on substring-scored cases the judge has since counted as
correct; it is not supported. Reports now record what was retrieved per case,
so the silent cases are diagnosable rather than arguable.

Reports are committed under `evals/reports/`; a diff between two of them is the
record of what a change actually did.

### Decisions worth explaining

**The gold set is held out, not hand-written.** The corpus already carries expert
labels - CWE, technique, severity.

**The secure half of each pair is the false-positive set.** A reviewer that flags
everything scores 100% detection and is useless, so `detection_rate` alone is a
vanity metric. `false_positive_rate` counts secure snippets flagged *for the
labelled class* - an earlier definition counting any finding at all sat at 1.000
and carried no signal, because a secure version fixes its own vulnerability and
not every unrelated wart.

**Cases are held out by content, not by id.** The corpus id is not an identifier:
`dataset.py` concatenates splits that each number from one, so
`authentication-000002` names 21 unrelated documents. Excluding by id would have
dropped roughly twenty innocent siblings per case and biased the RAG arm downward -
against the exact thing being measured.

**Detection is scored by an LLM judge, validated against human labels.** The
original substring probes marked 16 correct findings as misses and 5 wrong ones
as hits across both arms - a reviewer that wrote *"no authorization check on
admin routes"* was scored as missing *forced browsing*. The judge (`gemma4:e4b`,
deliberately not the reviewing model) asks whether a finding identifies the
labelled flaw in any wording; a finding that names the right line but claims
the wrong flaw is a miss. Verdicts are cached by content and prompt hash, so a
prompt edit cannot serve stale opinions. Against 30 human-labelled findings the
judge agrees at κ = 0.79, substring at 0.27 - but 8 of those items share a
technique with the prompt's worked examples, written from these same reports. On
the 22 that don't, **κ = 0.72 against 0.37**, and that is the number to trust. All
three judge errors were over-strict, never over-generous, so judged detection
rates are if anything low. The substring probes are kept (`--scorer substring`)
as the comparison point.

### Limitations

1. **n=39 is too small to settle the RAG question.** Three discordant detection
   pairs cannot resolve anything. The corpus holds 1,086 usable pairs.
2. **The false-positive rate is still substring-scored.** The original runs did
   not store secure-snippet findings, so the judge could not re-grade them. The
   harness now stores both; one fresh run corrects it.
3. **The judge is validated by one annotator, who is also the author,** on 30
   items. Two of its three errors are prompt-fixable - it graded a misstated
   impact instead of the flaw, and missed an alerting failure phrased as error
   handling - but fixing them against this sheet would spend its only
   uncontaminated items. The third is a label problem: *WebView security* is
   CWE-000, a category rather than a flaw.
4. **One case in the RAG arm failed to parse** under the earlier 1,536-token
   output cap, since raised to 3,072.

---

## Agents & Nodes

### Node 1 — Context (`get_context`)

**Purpose:** Cleans the raw git diff and extracts semantic context.

- **Diff Sanitisation** — Strips git headers (`+++`, `---`, `@@`) and leading `+`/` ` characters to produce clean source code.
- **LLM Semantic Extraction** — Calls `llama3.2` with structured output (`PRContext` schema) to identify:
  - `primary_language` — The programming language of the diff.
  - `imported_libraries` — Up to 3 core libraries/frameworks detected.
  - `core_concept` — A two-word summary of the code's purpose (e.g., *"SQL Query"*, *"File Upload"*).

**Output:** `sanitized_diff` and `pr_context` are written to state for all downstream nodes.

---

### Node 2 — Retrieve Examples (`retrieve_examples`)

**Purpose:** Performs **Retrieval-Augmented Generation** by querying ChromaDB for semantically similar vulnerability examples.

- Builds a search query by combining the `pr_context` metadata (language, libraries, concept) with the first 500 characters of the sanitised diff.
- Calls `vectorstore.search()` which embeds the query with `nomic-embed-text` and runs a cosine-similarity search against the `vulnerability_examples` collection.
- Returns the **top 3** most similar examples, including their document text, metadata, and distance scores.

**Why RAG?** The curated security dataset ([scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode)) contains labelled vulnerability examples with OWASP categories, CWE identifiers, severity levels, and remediation guidance, giving the Security Agent concrete patterns to reference instead of relying on parametric knowledge alone. What that is worth is an empirical question. Measured against a held-out set, retrieval made the reviewer *more conservative* - fewer false positives, fewer detections - with neither difference significant at n=39. See [Evaluation](#evaluation).

---

### Node 3a — Security Agent (`security_agent`) *runs in parallel*

**Purpose:** Analyses the sanitised diff for security vulnerabilities, guided by the retrieved examples.

- Receives both the code diff and the RAG-retrieved examples formatted as reference context.
- Uses structured output (`SecurityFindings` → list of `SecurityFinding`) to produce machine-parseable results.
- Each finding includes: `severity` (CRITICAL/HIGH/MEDIUM/LOW), `line_number`, `description`, and `fix`.
- Focus areas: injection flaws, auth issues, hardcoded secrets, insecure crypto, data exposure, input validation.

---

### Node 3b — Static Analysis Agent (`static_analysis_agent`) *runs in parallel*

**Purpose:** Checks the code for non-security quality issues.

- Analyses the diff with awareness of the detected language and frameworks (from `pr_context`).
- Uses structured output (`StaticFindings` → list of `StaticFinding`).
- Each finding includes: `category` (style/performance/maintainability/error-handling/best-practice), `line_number`, `description`, and `suggestion`.

**Fan-out:** Nodes 3a and 3b are dispatched as parallel branches, and their findings are merged into the shared state using `Annotated[List, operator.add]`, which safely concatenates results from both. They do not execute simultaneously in practice: both call one Ollama instance, which serialises them.

---

### Node 4 — Generate Final Review (`generate_final_review`)

**Purpose:** Aggregates all findings into a **Markdown report**.

The report contains:
- **PR Metadata** — Repository, PR number, author, commit hash, language, concept.
- **Verdict** — Automatically determined:
  - `CHANGES REQUESTED` if any CRITICAL findings.
  - `CHANGES REQUESTED` if any HIGH findings.
  - `APPROVED WITH SUGGESTIONS` if only MEDIUM/LOW findings.
  - `APPROVED` if clean.
- **Security Findings** — With severity categories.
- **Code Quality Findings** — Categorised by theme.

---

## Vector Store & Dataset Pipeline

### `dataset.py` — Data Ingestion

Downloads the [scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode) dataset from Hugging Face (web + AI/ML splits, **2,185 examples**). Uses `pandas` to handle mixed-type columns that break the standard `datasets.load_dataset()` loader, serialises problematic columns to JSON strings, and exports a clean `dataset.json`.

### `vectorstore.py` — Embedding & Retrieval

| Component | Detail |
|---|---|
| **Embedding model** | `nomic-embed-text` via Ollama (local, 8K-token context) |
| **Vector database** | ChromaDB with persistent file-backed storage (`chroma_db/`) |
| **Collection** | `vulnerability_examples` — 2,185 documents |
| **Document construction** | Each dataset entry is flattened into a single text document |
| **Deduplication** | Corpus ids are not identifiers: `dataset.py` concatenates splits that each number from one, so `authentication-000002` names 21 unrelated documents. Repeats are suffixed (`_dup1`, `_dup2`, …) at index time, and the evaluation holds cases out by content rather than by id. |
| **Batch embedding** | Processed in batches of 100 for efficient Ollama throughput |
| **Search** | Cosine similarity via `collection.query()`, returns top-*k* results with documents, metadata, and distances |

---

## Flask Webhook Server (`app.py`)

A minimal Flask server that acts as the entry point for the entire pipeline:

1. **Receives** GitHub `push` webhook events at `/`.
2. **Iterates** over each commit in the push payload.
3. **Fetches** the full commit details (including file-level patches) from the GitHub REST API.
4. **Extracts** metadata: commit hash, author, PR number (parsed from commit message via regex), repository name.
5. **Invokes** `run_review(raw_diff, pr_metadata)` for every changed file that has a patch.
6. **Returns** a JSON response containing all generated review reports.

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **[Ollama](https://ollama.com/)** installed and running locally
- Required Ollama models pulled:
  ```bash
  ollama pull llama3.2
  ollama pull nomic-embed-text
  ```

### Installation

```bash
# Clone the repository
git clone https://github.com/ErjonFida/Code_Review_Agent
cd Code_Review_Agent

# Install Python dependencies
pip install -r requirements.txt
```

### Build the Vector Store (one-time)

```bash
# 1. Download and prepare the dataset
python dataset.py

# 2. Embed and index into ChromaDB (~30 min on first run on Ultra 9h CPU)
python vectorstore.py

# To force a full rebuild:
python vectorstore.py --rebuild
```

### Run the Agent

**Option A — Standalone test (no GitHub required):**

```bash
python graph.py
```

This runs a mock review against a hardcoded SQL injection example and prints the full Markdown report.

**Option B — Webhook server (production flow):**

```bash
python app.py
```

The Flask server starts on `http://localhost:3000`. Configure your GitHub repository's webhook to point to this URL (use a tunnel like [smee.io](https://smee.io/)).

### Run the Evaluation

```bash
# Build the held-out gold set (one-time, writes evals/datasets/gold.jsonl)
python -m evals.build_gold --n 40

# Score the security agent, with and without retrieval
python -m evals.run --label baseline-rag
python -m evals.run --label baseline-no-rag --no-rag

# Scoring tests only, no LLM required
python -m evals.run --self-check

# Re-grade an existing report with the judge; label and score its validation sheet
python -m evals.judge rescore evals/reports/baseline-rag.json
python -m evals.judge label
python -m evals.judge agreement
```

`REVIEW_MODEL` selects the reviewing model (default `llama3.2`), and every report
records which model produced it, so results from different models can sit side by
side.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Orchestration** | LangGraph (StateGraph with fan-out/fan-in) |
| **LLM** | Llama 3.2 via Ollama (local inference) |
| **Embeddings** | nomic-embed-text via Ollama |
| **Vector Store** | ChromaDB (persistent, file-backed) |
| **Structured Output** | Pydantic v2 schemas + LangChain `with_structured_output` |
| **Web Framework** | Flask |
| **Dataset** | [scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode) (Hugging Face) |
| **VCS Integration** | GitHub Webhooks + REST API |
| **Evaluation** | 40 held-out CWE-labelled cases, LLM-judged, McNemar paired test (`evals/`) |

---

## Next

In order, each measured against the committed baseline, one change at a time:

1. **Re-run both arms** so false positives are judge-scored and every case
   records what was retrieved.
2. **Diagnose the silent cases.** If retrieval returned a different vulnerability
   class than the one in the code, the suppression has a cause and a fix.
3. **Widen the gold set to ~200 cases**, dropping CWE-000 labels, and validate a
   revised judge on a fresh sheet. Three discordant pairs cannot settle
   whether retrieval helps; the corpus holds 1,086 usable pairs.
4. **Compare models.** `gemma4:e4b` measures at 74 s/snippet against `llama3.2`'s
   20 s, a 3.3-hour ablation that `REVIEW_MODEL` already supports.

---

## License

MIT
