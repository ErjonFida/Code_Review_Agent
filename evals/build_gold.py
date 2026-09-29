import argparse
import hashlib
import json
import os
import random
import re
from collections import Counter

from vectorstore import _entry_to_document

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_DIR, "dataset.json")
GOLD_PATH = os.path.join(PROJECT_DIR, "evals", "datasets", "gold.jsonl")

VULN_RE = re.compile(r"\*\*VULNERABLE CODE\*\*.*?```[a-zA-Z]*\n(.*?)```", re.S)
SECURE_RE = re.compile(r"\*\*SECURE VERSION\*\*.*?```[a-zA-Z]*\n(.*?)```", re.S)

MAX_SNIPPET_CHARS = 4000
MIN_SNIPPET_CHARS = 100
MAX_PER_TECHNIQUE = 2
PROBE_CHARS = 120

# Words that appear in a technique name but identify no vulnerability class.
STOPWORDS = {
    "attack", "attacks", "prevention", "protection", "handling", "based",
    "insecure", "unsafe", "improper", "incorrect", "missing", "weak", "bad",
    "vulnerability", "vulnerabilities", "issue", "issues", "risk", "flaw",
    "code", "level", "function", "using", "with", "from", "user", "data",
    "model", "access", "object", "reference", "control", "input", "output",
    "service", "application", "security", "general", "system", "server",
}


def probes(technique: str) -> list[str]:
    
    tokens = [t for t in re.split(r"[^a-z0-9]+", technique.lower()) if len(t) >= 4]
    return sorted({t[:8] for t in tokens if t not in STOPWORDS})


def _first_block(pattern: re.Pattern, text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    code = match.group(1).strip()
    return code[:MAX_SNIPPET_CHARS] if len(code) >= MIN_SNIPPET_CHARS else None


def candidates(dataset: list[dict]) -> list[dict]:
    
    out, seen_content = [], set()

    for entry in dataset:
        assistant = "\n".join(
            turn.get("content", "")
            for turn in entry.get("conversations", [])
            if turn.get("role") == "assistant"
        )
        vulnerable = _first_block(VULN_RE, assistant)
        secure = _first_block(SECURE_RE, assistant)
        if not vulnerable or not secure:
            continue

        digest = hashlib.sha256(vulnerable.encode("utf-8")).hexdigest()
        if digest in seen_content:
            continue
        seen_content.add(digest)

        try:
            meta = json.loads(entry.get("metadata") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue

        technique = str(meta.get("technique", "")).strip()
        must_match = probes(technique)
        if not must_match:

            continue

        document = _entry_to_document(entry)
        context = str(entry.get("context") or "")
        exclude_probes = [
            probe for probe in (vulnerable[:PROBE_CHARS], context[:PROBE_CHARS])
            if probe.strip() and probe in document
        ][:1]
        if not exclude_probes:
            continue

        out.append({
            "case_id": f"{entry.get('id', 'entry')}-{digest[:8]}",
            "corpus_id": entry.get("id"),
            "lang": meta.get("lang", "unknown"),
            "technique": technique,
            "cwe": meta.get("cwe", ""),
            "severity": meta.get("severity", ""),
            "must_match": must_match,
            "exclude_probes": exclude_probes,
            "vulnerable_code": vulnerable,
            "secure_code": secure,
        })
    return out


def sample(rows: list[dict], n: int, seed: int) -> list[dict]:

    random.Random(seed).shuffle(rows)
    per_technique: Counter = Counter()
    chosen = []
    for row in rows:
        key = row["technique"].lower().replace(" ", "_")
        if per_technique[key] >= MAX_PER_TECHNIQUE:
            continue
        per_technique[key] += 1
        chosen.append(row)
        if len(chosen) == n:
            break
    return sorted(chosen, key=lambda r: r["case_id"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the held-out gold set.")
    parser.add_argument("--n", type=int, default=40, help="vulnerable/secure pairs to sample")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default=GOLD_PATH)
    parser.add_argument("--exclude", default=None,
                        help="existing set whose cases must not reappear, e.g. gold.jsonl when building a dev set")
    args = parser.parse_args()

    if not os.path.exists(DATASET_PATH):
        raise SystemExit(f"No corpus at {DATASET_PATH}. Run: python dataset.py")

    print(f"Loading {DATASET_PATH}...")
    with open(DATASET_PATH, encoding="utf-8") as fh:
        dataset = json.load(fh)

    rows = candidates(dataset)
    print(f"{len(rows)} of {len(dataset)} entries carry a distinct, scoreable pair")

    if args.exclude:
        # By content, not id: corpus ids repeat across unrelated documents.
        def digest(code): return hashlib.sha256(code.encode("utf-8")).hexdigest()
        with open(args.exclude, encoding="utf-8") as fh:
            taken = {digest(json.loads(l)["vulnerable_code"]) for l in fh if l.strip()}
        rows = [r for r in rows if digest(r["vulnerable_code"]) not in taken]
        print(f"{len(rows)} remain after excluding the {len(taken)} cases in {os.path.basename(args.exclude)}")

    chosen = sample(rows, args.n, args.seed)
    if len(chosen) < args.n:
        print(f"WARNING: only {len(chosen)} pairs available under the per-technique cap")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        for row in chosen:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Wrote {len(chosen)} cases to {args.out}")
    print(f"  languages : {dict(Counter(r['lang'] for r in chosen))}")
    print(f"  severity  : {dict(Counter(r['severity'] for r in chosen))}")
    print(f"  techniques: {len(set(r['technique'] for r in chosen))} distinct")
    print("\nThese documents stay out of retrieval - evals.run excludes them by content.")


if __name__ == "__main__":
    main()
