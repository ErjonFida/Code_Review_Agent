# AI Code Review Agent

A security reviewer for GitHub pull requests that runs entirely on your machine.
It reviews every changed file with a local LLM and posts its findings as a comment
on the pull request - no code leaves the machine.

| Measured on 40 held-out, expert-labelled vulnerabilities | |
|---|---:|
| vulnerabilities caught | **97%** |
| fixed code wrongly flagged for the same flaw | **18%** (from 44% with the previous model, McNemar p = 0.04) |
| agreement of the automated scorer with human labels | Cohen's kappa **0.89** (0.84 including the items its prompt was tuned on) |

Full method, results and experiment history: [evals/README.md](evals/README.md).

---

## A Code Review Agent with a RAG Pipeline

A retrieval-augmented reviewer, then an evaluation to prove retrieval
helped. The evaluation's first scorer was wrong a third of the time, so I replaced
it with an LLM judge and validated that against my own labels. Measured properly,
retrieval did not improve what the reviewer caught - it made the reviewer copy its
examples' vulnerability names into findings - so it now runs only on very large
diffs. A prompt change that looked good on the development set failed the held-out
test and was reverted; a model change passed it and shipped.

The last two were decided by a rule committed before the result it judged was
read, so the bar could not move to fit the answer.

---

## How it works

```
GitHub pull request (opened / synchronize / reopened)
        |  webhook, signed with HMAC-SHA256
        v
app.py (Flask) - verifies the signature, answers 202 at once,
        |        reviews in a background thread
        |  fetches each changed file's patch from the GitHub API
        v
LangGraph pipeline, once per file
        1. Context: language, libraries and purpose of the code
        2. Retrieval: similar vulnerability examples (ChromaDB) - large diffs only
        3a. Security agent          3b. Code-quality agent      (fan-out)
        4. Markdown report: verdict, findings by severity, fixes
        |
        v
One comment on the pull request
```

| Decision | Why |
|---|---|
| **Local model** (`qwen3.5:9b` via Ollama) | Proprietary code never leaves the machine and there is no API bill. It replaced `llama3.2`, which produced as many findings on fixed code as on vulnerable code (4.05 each) and so could not tell them apart. |
| **Structured output** | Every model call returns a Pydantic schema, so a malformed answer fails loudly instead of being guessed at. |
| **Retrieval only above 20,000 characters** | On the diffs the evaluation covers it gave no measurable benefit and copied its examples' vulnerability names into 14% of findings. Whether it helps on large diffs is untested. |
| **Signature check, then 202** | An unsigned request could make the bot spend minutes of compute and comment on any pull request the token can reach. GitHub records any delivery slower than 10 s as failed, so the review runs after the reply. |
| **One failing file does not sink the review** | It is reported in the comment and the other files' findings are kept. |

---

## Setup

**Requirements:** Python 3.10+, [Ollama](https://ollama.com/) **0.35.0 or later**,
and about 16 GB of free RAM for the reviewing model. A review takes about a minute
per file on a laptop CPU.

```bash
git clone https://github.com/ErjonFida/Code_Review_Agent
cd Code_Review_Agent
pip install -r requirements.txt

ollama pull qwen3.5:9b         # the reviewer
ollama pull nomic-embed-text   # embeddings for the retrieval index

# One-time: download the securecode corpus and index it (~30 min on CPU)
python dataset.py
python vectorstore.py
```

**Try it without GitHub:** `python graph.py` reviews a built-in SQL injection
example and prints the report.

**Connect it to a repository:**

1. `cp .env.example .env`, then set `GITHUB_TOKEN` (a fine-grained token for the
   repository, with *Pull requests: Read and write*) and `GITHUB_WEBHOOK_SECRET`
   (any long random string, e.g. `python -c "import secrets; print(secrets.token_hex(32))"`).
2. `python app.py` - it listens on `http://localhost:3000`.
3. Expose that port with a tunnel that forwards requests unchanged, such as
   `cloudflared tunnel --url http://localhost:3000` or ngrok. (smee re-serialises
   the request body, which can break the signature check.)
4. In the repository's *Settings -> Webhooks*, add the tunnel URL with content type
   `application/json`, the same secret, and only *Pull requests* events.

Open a pull request and the review appears as a comment.

**Tests:** `python test_app.py` - webhook security, comment assembly, the report
format and the retrieval routing, with no model or network needed.

---

## Known limitations

- **Line numbers are counted by the model** and are often a few lines off.
- **The code-quality agent is not evaluated**, and tends to repeat the security
  findings as "best practice" suggestions.
- **About a minute per file and 16 GB of RAM.** The previous model was 2.3x faster
  and caught nearly as much, but raised more than twice the false alarms.
- **The evaluation is 40 cases**, and its held-out set has now informed three
  decisions; see [evals/README.md](evals/README.md#limitations).

---

## Tech stack

| Layer | Technology |
|---|---|
| Orchestration | LangGraph |
| Reviewing model | qwen3.5:9b via Ollama, thinking off |
| Retrieval | ChromaDB 1.5.9, nomic-embed-text embeddings, 2,185 examples from [scthornton/securecode](https://huggingface.co/datasets/scthornton/securecode) |
| Structured output | Pydantic v2 with LangChain `with_structured_output` |
| Webhook server | Flask, GitHub REST API |
| Evaluation | Held-out CWE-labelled pairs, gemma4:e4b judge validated against human labels, McNemar paired test (`evals/`) |

---

## License

MIT
