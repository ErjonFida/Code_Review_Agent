import argparse
import hashlib
import json
import os
import random

from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(PROJECT_DIR, "evals", "reports")
CACHE_PATH = os.path.join(PROJECT_DIR, "evals", ".cache", "judge.json")
SHEET_PATH = os.path.join(PROJECT_DIR, "evals", "datasets", "judge_validation.jsonl")

# Not the reviewing model: a judge from the same family shares its blind spots.
JUDGE_MODEL = os.getenv("JUDGE_MODEL", "gemma4:e4b")

SYSTEM_PROMPT = """You grade code-review findings.

A reviewer was shown code containing ONE known vulnerability. You are given that
vulnerability's class and a single finding the reviewer produced about that code.
You do not see the code. Decide whether the flaw the finding claims is the
labelled vulnerability - the same underlying flaw, in any wording.

- Vocabulary does not matter; the flaw does. IDOR, broken object-level
  authorization and horizontal privilege escalation are one flaw; a missing
  lockout and unlimited password attempts are one flaw; a wildcard dependency
  version is a supply-chain flaw.
- The class label may be named after the DEFENSE rather than the flaw. "Strong
  parameters" means mass assignment through unfiltered request parameters;
  "Password hashing with argon2" means weak, fast or unsalted password hashing.
  Translate the label into the flaw it implies before comparing.
- A finding about a DIFFERENT flaw in the same code does not count, even if that
  flaw is real. Hardcoded credentials found in SQL-injection code is not a
  SQL-injection finding.
- A finding whose description claims a different flaw does not count just
  because its fix text mentions the class.
- Do not require the finding to prove the flaw exists; the reviewer saw the code
  and you did not. Judge only whether the claimed flaw is the labelled one."""


# A prompt change must invalidate every cached verdict, or the cache quietly
# reports the old judge's opinions as the new judge's.
PROMPT_ID = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()[:12]


class Verdict(BaseModel):
    describes: bool = Field(
        description="True only if the finding identifies the same underlying flaw as the labelled class.")
    reason: str = Field(description="One sentence.")


_cache: dict | None = None
_chain = None


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH, encoding="utf-8") as fh:
                _cache = json.load(fh)
        except (OSError, json.JSONDecodeError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(_cache, fh, indent=1)


def _get_chain():
    global _chain
    if _chain is None:
        # gemma4 reasons for ~270 hidden tokens before a one-word answer, so a
        # tight cap returns an empty completion; 1024 leaves room for the verdict.
        llm = ChatOllama(model=JUDGE_MODEL, temperature=0, num_predict=1024)
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", "Vulnerability class: {technique} ({cwe})\n\n"
                      "Finding:\n{description}\n\nSuggested fix:\n{fix}"),
        ])
        _chain = prompt | llm.with_structured_output(Verdict)
    return _chain


def describes(technique: str, cwe: str, finding: dict) -> dict:
    description = finding.get("description", "") or ""
    fix = finding.get("fix", "") or ""
    key = hashlib.sha256(
        f"{JUDGE_MODEL}|{PROMPT_ID}|{technique}|{cwe}|{description}|{fix}".encode("utf-8")).hexdigest()

    cache = _load_cache()
    if key in cache:
        return cache[key]

    verdict = _get_chain().invoke({
        "technique": technique or "unknown",
        "cwe": cwe or "unknown",
        "description": description or "(empty)",
        "fix": fix or "(none given)",
    })
    cache[key] = {"describes": bool(verdict.describes), "reason": verdict.reason}
    _save_cache()
    return cache[key]


def matching_finding(findings: list[dict], technique: str, cwe: str) -> dict | None:
    for finding in findings:
        if describes(technique, cwe, finding)["describes"]:
            return finding
    return None



def _stored_findings(result: dict, side: str) -> list[dict] | None:

    full = result.get(f"{side}_findings_list")
    if full is not None:
        return full
    if side == "vuln" and "vuln_descriptions" in result:
        return [{"description": d} for d in result["vuln_descriptions"]]
    return None


def rescore(report_path: str, out_path: str | None) -> dict:
    from . import run as runner

    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)

    results = []
    substring_agree = total = 0
    secure_rescored = True

    for r in report["results"]:
        if r.get("error"):
            results.append(r)
            continue
        r = dict(r)
        technique, cwe = r["technique"], r.get("cwe", "")

        vuln = _stored_findings(r, "vuln") or []
        hit = matching_finding(vuln, technique, cwe)
        r["detected_substring"] = r["detected"]
        r["detected"] = hit is not None
        if hit is None:
            r["severity_match"] = False
        elif "severity" in hit:
            r["severity_match"] = hit.get("severity") == r.get("severity")
        # else: the source report stored descriptions only; keep its value.
        substring_agree += r["detected"] == r["detected_substring"]
        total += 1

        secure = _stored_findings(r, "secure")
        if secure is None:
            secure_rescored = False
        else:
            r["secure_flagged_substring"] = r["secure_flagged"]
            r["secure_flagged"] = matching_finding(secure, technique, cwe) is not None

        results.append(r)
        print(f"  {r['id'][:40]:<40} detected {r['detected_substring']!s:<5} -> {r['detected']!s:<5}")

    report["label"] = f"{report['label']}-judged"
    report["config"]["scorer"] = {
        "detection": f"judge/{JUDGE_MODEL}",
        "false_positive": f"judge/{JUDGE_MODEL}" if secure_rescored
        else "substring (secure findings not stored in the source report)",
        "rescored_from": os.path.basename(report_path),
    }
    report["metrics"] = runner.aggregate(results)
    report["misses"] = runner.misses(results)
    report["results"] = results
    report["scorer_agreement"] = {
        "detection_cases": total,
        "substring_agrees_with_judge": substring_agree,
        "rate": round(substring_agree / total, 4) if total else 0.0,
    }

    out = out_path or os.path.join(REPORT_DIR, f"{report['label']}.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2)

    o = report["metrics"]["overall"]
    print(f"\n  {report['label']}")
    print(f"    detection_rate       {o['detection_rate']:.3f}   (was {sum(r.get('detected_substring', 0) for r in results if not r.get('error')) / max(total, 1):.3f} by substring)")
    print(f"    false_positive_rate  {o['false_positive_rate']:.3f}   ({report['config']['scorer']['false_positive']})")
    print(f"    substring/judge agreement on detection: {substring_agree}/{total}")
    print(f"  Report written to {out}\n")
    return report


def build_sheet(report_paths: list[str], n: int, seed: int) -> None:

    from .run import matching_finding as substring_match

    pool = []
    for path in report_paths:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
        for r in report["results"]:
            if r.get("error"):
                continue
            for finding in _stored_findings(r, "vuln") or []:
                pool.append({
                    "case_id": r["id"],
                    "arm": report["config"]["arm"],
                    "technique": r["technique"],
                    "cwe": r.get("cwe", ""),
                    "description": finding.get("description", ""),
                    "fix": finding.get("fix", ""),
                    "substring_describes": substring_match([finding], r["must_match"]) is not None,
                    "case_detected_by_substring": r["detected"],
                })

    rng = random.Random(seed)
    missed = [p for p in pool if not p["case_detected_by_substring"]]
    hit = [p for p in pool if p["case_detected_by_substring"] and p["substring_describes"]]
    rng.shuffle(missed)
    rng.shuffle(hit)
    chosen = missed[: n // 2] + hit[: n - n // 2]

    os.makedirs(os.path.dirname(SHEET_PATH), exist_ok=True)
    with open(SHEET_PATH, "w", encoding="utf-8", newline="\n") as fh:
        for item in chosen:
            verdict = describes(item["technique"], item["cwe"],
                                {"description": item["description"], "fix": item["fix"]})
            item["judge_describes"] = verdict["describes"]
            item["judge_reason"] = verdict["reason"]
            item["human_describes"] = None
            item.pop("case_detected_by_substring")
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
            print(f"  [{'judge:' + str(verdict['describes']):<12}] {item['technique'][:32]:<32} {item['description'][:60]}")

    print(f"\n  {len(chosen)} items written to {SHEET_PATH}")
    print("  Fill in human_describes (true/false) for each, then: python -m evals.judge agreement")


def label() -> None:
    rows = [json.loads(l) for l in open(SHEET_PATH, encoding="utf-8") if l.strip()]
    todo = [i for i, r in enumerate(rows) if r.get("human_describes") is None]
    print(f"{len(todo)} of {len(rows)} rows unlabelled. Does the finding describe the class? y / n / s(kip) / q(uit)\n")

    for done, i in enumerate(todo, start=1):
        r = rows[i]
        print(f"[{done}/{len(todo)}]  CLASS: {r['technique']}  ({r['cwe']})")
        print(f"   FINDING: {r['description']}")
        if r.get("fix"):
            print(f"   FIX:     {r['fix'][:200]}")
        while True:
            try:
                answer = input("   describes the class? [y/n/s/q] ").strip().lower()
            except EOFError:
                answer = "q"
            if answer in ("y", "n", "s", "q"):
                break
        if answer == "q":
            break
        if answer == "s":
            print()
            continue
        r["human_describes"] = answer == "y"
        with open(SHEET_PATH, "w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print()

    remaining = sum(1 for r in rows if r.get("human_describes") is None)
    print(f"{len(rows) - remaining} labelled, {remaining} remaining."
          + ("" if remaining else "  Now: python -m evals.judge agreement"))


def agreement() -> None:
    rows = [json.loads(l) for l in open(SHEET_PATH, encoding="utf-8") if l.strip()]
    labelled = [r for r in rows if r.get("human_describes") is not None]
    if not labelled:
        raise SystemExit(f"No human labels in {SHEET_PATH} yet.")

    def kappa(pred: str) -> float:
        n = len(labelled)
        agree = sum(r[pred] == r["human_describes"] for r in labelled)
        p_yes_pred = sum(r[pred] for r in labelled) / n
        p_yes_human = sum(r["human_describes"] for r in labelled) / n
        expected = p_yes_pred * p_yes_human + (1 - p_yes_pred) * (1 - p_yes_human)
        observed = agree / n
        return round((observed - expected) / (1 - expected), 3) if expected < 1 else 1.0

    def accuracy(pred: str) -> float:
        return round(sum(r[pred] == r["human_describes"] for r in labelled) / len(labelled), 3)

    print(f"\n  {len(labelled)} of {len(rows)} items labelled\n")
    print(f"    judge      accuracy {accuracy('judge_describes'):.3f}   kappa {kappa('judge_describes'):.3f}")
    print(f"    substring  accuracy {accuracy('substring_describes'):.3f}   kappa {kappa('substring_describes'):.3f}")

    disagreements = [r for r in labelled if r["judge_describes"] != r["human_describes"]]
    print(f"\n  Judge disagreed with you on {len(disagreements)}:")
    for r in disagreements:
        print(f"    [{r['technique'][:30]:<30}] judge={r['judge_describes']} you={r['human_describes']}: "
              f"{r['description'][:70]}")
        print(f"      judge's reason: {r['judge_reason'][:100]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM judge for evaluation scoring.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("rescore", help="re-grade an existing report with the judge")
    p.add_argument("report")
    p.add_argument("--out", default=None)

    p = sub.add_parser("sheet", help="build the human-validation sheet")
    p.add_argument("--reports", nargs="+", default=[
        os.path.join(REPORT_DIR, "baseline-rag.json"),
        os.path.join(REPORT_DIR, "baseline-no-rag.json"),
    ])
    p.add_argument("--n", type=int, default=30)
    p.add_argument("--seed", type=int, default=0)

    sub.add_parser("label", help="fill in human labels interactively")
    sub.add_parser("agreement", help="score the sheet against human labels")

    args = parser.parse_args()
    print(f"judge model: {JUDGE_MODEL}")
    if args.cmd == "rescore":
        rescore(args.report, args.out)
    elif args.cmd == "sheet":
        build_sheet(args.reports, args.n, args.seed)
    elif args.cmd == "label":
        label()
    else:
        agreement()


if __name__ == "__main__":
    main()
