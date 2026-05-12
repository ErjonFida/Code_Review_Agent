# AI Code Review Agent

An **automated, multi-agent code review system** built with [LangGraph](https://langchain-ai.github.io/langgraph/), [Ollama](https://ollama.com/) (Llama 3.2), and [ChromaDB](https://www.trychroma.com/). The agent listens for GitHub `push` events via a webhook, analyses every changed file in each commit, and produces a structured Markdown review report covering **security vulnerabilities** and **code quality** issues.

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
| **LangGraph over a simple chain** | LangGraph enables parallel execution for the security and static agents, reducing latency compared to sequential execution. The `Annotated[List, operator.add]` prevents overwriting. |
| **Ollama (local LLM)** | Runs locally via `llama3.2`, avoids API costs and keeps code private — suitable for proprietary source. |
| **Structured output (Pydantic)** | Every LLM call uses `with_structured_output(PydanticModel)` to guarantee machine-parseable JSON.
| **ChromaDB (persistent vector store)** | A local, file-backed vector database stores 2,185 embedded vulnerability examples. Persistence avoids re-embedding on every restart (~30 min to build on CPU). |
| **nomic-embed-text embeddings** | A lightweight embedding model that runs locally via Ollama.
| **RAG for security guidance** | Rather than relying solely on the LLM's parametric knowledge, the pipeline retrieves the 3 most semantically similar vulnerability examples from a curated dataset. This grounds the security agent's analysis in real-world patterns and reduces hallucination. |
| **Diff sanitisation before analysis** | Git noise (`+++`, `---`, `@@` headers) is stripped in Node 1 so downstream agents only see meaningful code — improving embedding relevance and LLM focus. |

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

**Why RAG?** The curated security dataset ([scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode)) contains labelled vulnerability examples with OWASP categories, CWE identifiers, severity levels, and remediation guidance. Retrieving relevant examples gives the Security Agent concrete, real-world patterns to reference — dramatically improving the specificity and accuracy of its findings versus zero-shot prompting alone.

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

**Parallel execution:** Nodes 3a and 3b run concurrently via LangGraph's fan-out edges. Their findings are merged into the shared state using `Annotated[List, operator.add]`, which safely concatenates results from both branches.

---

### Node 4 — Generate Final Review (`generate_final_review`)

**Purpose:** Aggregates all findings into a polished, emoji-rich **Markdown report**.

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
| **Deduplication** | Duplicate IDs across dataset splits are suffixed (`_dup1`, `_dup2`, …) |
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

---

## License

This project was built as a capstone project for a LangGraph and RAG course.
