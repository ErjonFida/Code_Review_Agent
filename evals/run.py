import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone

from graph import MODEL, get_context, retrieve_examples, security_agent
from evals import judge

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLD_PATH = os.path.join(PROJECT_DIR, "evals", "datasets", "gold.jsonl")
REPORT_DIR = os.path.join(PROJECT_DIR, "evals", "reports")

HIGH_SEVERITY = {"CRITICAL", "HIGH"}
EXT = {
    "python": "py", "javascript": "js", "typescript": "ts", "java": "java",
    "go": "go", "csharp": "cs", "php": "php", "ruby": "rb", "kotlin": "kt",
    "yaml": "yaml", "c": "c", "cpp": "cpp", "rust": "rs",
}


def load_gold(path: str) -> list[dict]:
    
    cases, seen = [], set()
    if not os.path.exists(path):
        raise SystemExit(f"No gold set at {path}. Run: python -m evals.build_gold")

    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"{os.path.basename(path)}:{line_no} is not valid JSON: {e}")

            for field in ("case_id", "must_match", "exclude_probes",
                          "vulnerable_code", "secure_code", "technique"):
                if not row.get(field):
                    raise SystemExit(f"{os.path.basename(path)}:{line_no} is missing '{field}'")
            if row["case_id"] in seen:
                raise SystemExit(
                    f"{os.path.basename(path)}:{line_no} duplicates case_id '{row['case_id']}'")
            seen.add(row["case_id"])
            cases.append(row)

    if not cases:
        raise SystemExit(f"{path} contains no cases")
    return cases


def as_diff(code: str, filename: str) -> str:
    
    lines = code.splitlines() or [""]
    header = (f"diff --git a/{filename} b/{filename}\n"
              f"--- /dev/null\n+++ b/{filename}\n@@ -0,0 +1,{len(lines)} @@\n")
    return header + "\n".join("+" + line for line in lines)


def matching_finding(findings: list[dict], must_match: list[str]) -> dict | None:
    for finding in findings:
        text = f"{finding.get('description', '')} {finding.get('fix', '')}".lower()
        if any(probe in text for probe in must_match):
            return finding
    return None


def _retrieved_technique(example: dict) -> str | None:
    try:
        return json.loads(example.get("metadata", {}).get("metadata_str", "")).get("technique")
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None


def review(code: str, case: dict, use_rag: bool, exclude: list[str]) -> tuple[list[dict], float, list[dict]]:
    """(findings, latency_ms, retrieved) - retrieved is what RAG put in front of
    the model for this snippet, so a silent or misdirected case can be diagnosed."""
    filename = f"snippet.{EXT.get(case.get('lang', ''), 'txt')}"
    state = {"raw_diff": as_diff(code, filename), "exclude_snippets": exclude}

    started = time.perf_counter()
    state.update(get_context(state))
    if use_rag:
        state.update(retrieve_examples(state))
    else:
        state["retrieved_examples"] = []
    findings = security_agent(state)["security_findings"]
    retrieved = [
        {"id": r["id"], "distance": round(r["distance"], 4), "technique": _retrieved_technique(r)}
        for r in state["retrieved_examples"]
    ]
    return findings, (time.perf_counter() - started) * 1000, retrieved


def _percentile(values: list[float], pct: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(round((pct / 100) * (len(ordered) - 1))), len(ordered) - 1)
    return round(ordered[index], 2)


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def aggregate(results: list[dict]) -> dict:
    scored = [r for r in results if not r.get("error")]
    latencies = [ms for r in scored for ms in (r["vuln_latency_ms"], r["secure_latency_ms"])]
    detected = [r for r in scored if r["detected"]]

    by_severity: dict[str, dict] = {}
    for severity in sorted({r["severity"] for r in scored}):
        rows = [r for r in scored if r["severity"] == severity]
        by_severity[severity] = {
            "cases": len(rows),
            "detection_rate": _rate(sum(r["detected"] for r in rows), len(rows)),
        }

    by_language: dict[str, dict] = {}
    for lang in sorted({r["lang"] for r in scored}):
        rows = [r for r in scored if r["lang"] == lang]
        by_language[lang] = {
            "cases": len(rows),
            "detection_rate": _rate(sum(r["detected"] for r in rows), len(rows)),
        }

    return {
        "overall": {
            "cases": len(scored),
            "detection_rate": _rate(len(detected), len(scored)),
            "false_positive_rate": _rate(sum(r["secure_flagged"] for r in scored), len(scored)),
            "secure_any_finding_rate": _rate(sum(r["secure_any_finding"] for r in scored), len(scored)),
            "high_severity_fp_rate": _rate(sum(r["secure_flagged_high"] for r in scored), len(scored)),
            "severity_match": _rate(sum(r["severity_match"] for r in detected), len(detected)),
            "findings_per_vulnerable_case": round(
                sum(r["vuln_findings"] for r in scored) / len(scored), 2) if scored else 0.0,
            "findings_per_secure_case": round(
                sum(r["secure_findings"] for r in scored) / len(scored), 2) if scored else 0.0,
            "p50_latency_ms": _percentile(latencies, 50),
            "p95_latency_ms": _percentile(latencies, 95),
        },
        "by_severity": by_severity,
        "by_language": by_language,
        "errors": len(results) - len(scored),
    }


def misses(results: list[dict]) -> list[dict]:
    
    return [
        {
            "id": r["id"],
            "technique": r["technique"],
            "cwe": r["cwe"],
            "expected_terms": r["must_match"],
            "said": r["vuln_descriptions"],
        }
        for r in results if not r.get("error") and not r["detected"]
    ]


def score(findings: list[dict], case: dict, scorer: str) -> dict | None:
    if scorer == "judge":
        return judge.matching_finding(findings, case["technique"], case.get("cwe", ""))
    return matching_finding(findings, case["must_match"])


def run(cases: list[dict], use_rag: bool, scorer: str = "judge") -> list[dict]:

    exclude = [probe for c in cases for probe in c["exclude_probes"]]
    results = []

    for index, case in enumerate(cases, start=1):
        print(f"\n--- [{index}/{len(cases)}] {case['case_id']} ({case['technique']}) ---")
        try:
            vuln_findings, vuln_ms, vuln_retrieved = review(case["vulnerable_code"], case, use_rag, exclude)
            secure_findings, secure_ms, secure_retrieved = review(case["secure_code"], case, use_rag, exclude)
        except Exception as e:
            # A structured-output parse failure should cost one case, not the run.
            print(f"  ERROR: {type(e).__name__}: {e}")
            results.append({"id": case["case_id"], "error": f"{type(e).__name__}: {e}"})
            continue

        hit = score(vuln_findings, case, scorer)
        secure_hit = score(secure_findings, case, scorer)
        results.append({
            "id": case["case_id"],
            "technique": case["technique"],
            "cwe": case.get("cwe", ""),
            "lang": case.get("lang", "unknown"),
            "severity": case.get("severity", ""),
            "must_match": case["must_match"],
            "detected": hit is not None,
            "severity_match": bool(hit) and hit.get("severity") == case.get("severity"),
            "vuln_findings": len(vuln_findings),
            "vuln_descriptions": [f.get("description", "") for f in vuln_findings],
            "vuln_findings_list": vuln_findings,
            "secure_findings_list": secure_findings,
            "vuln_retrieved": vuln_retrieved,
            "secure_retrieved": secure_retrieved,
            "secure_findings": len(secure_findings),
            "secure_flagged": secure_hit is not None,
            "secure_any_finding": len(secure_findings) > 0,
            "secure_flagged_high": any(
                f.get("severity") in HIGH_SEVERITY for f in secure_findings),
            "vuln_latency_ms": round(vuln_ms, 2),
            "secure_latency_ms": round(secure_ms, 2),
        })
        print(f"  detected={hit is not None}  false_positive={secure_hit is not None}")

    return results


def print_report(report: dict) -> None:
    overall = report["metrics"]["overall"]
    print(f"\n  {report['label']}  |  {report['config']['arm']}  |  {report['config']['model']}")
    print(f"  {overall['cases']} scored cases, {report['metrics']['errors']} errors\n")
    print(f"    detection_rate        {overall['detection_rate']:.3f}   (vulnerable snippet flagged correctly)")
    print(f"    false_positive_rate   {overall['false_positive_rate']:.3f}   (secure snippet flagged for the same class)")
    print(f"    secure_any_finding    {overall['secure_any_finding_rate']:.3f}   (secure snippet flagged for anything)")
    print(f"    high_severity_fp_rate {overall['high_severity_fp_rate']:.3f}")
    print(f"    severity_match        {overall['severity_match']:.3f}   (of detections)")
    print(f"    findings/case         {overall['findings_per_vulnerable_case']:.2f} vulnerable, "
          f"{overall['findings_per_secure_case']:.2f} secure")
    print(f"    latency               p50 {overall['p50_latency_ms']:.0f}ms   p95 {overall['p95_latency_ms']:.0f}ms")

    print("\n  Detection by severity")
    for severity, block in report["metrics"]["by_severity"].items():
        print(f"    {severity:<10} {block['detection_rate']:.3f}   ({block['cases']} cases)")

    print(f"\n  Missed: {len(report['misses'])}")
    for miss in report["misses"][:5]:
        said = (miss["said"][0][:60] + "...") if miss["said"] else "nothing"
        print(f"    {miss['id']} [{miss['technique']}] said: {said}")
    if len(report["misses"]) > 5:
        print(f"    ... and {len(report['misses']) - 5} more (see the report file)")


def self_check() -> None:
    """The two pieces that fail silently: the diff shim and the scorer."""
    code = "import sqlite3\nquery = 'SELECT * FROM users WHERE u = ' + name\ncur.execute(query)"
    diff = as_diff(code, "snippet.py")
    kept = [line[1:] for line in diff.split("\n")
            if line.startswith("+") and not line.startswith("+++")]
    assert "\n".join(kept) == code, "as_diff does not survive the pipeline's sanitiser"

    findings = [
        {"description": "Unvalidated input reaches the query", "fix": "Use parameterised statements"},
        {"description": "SQL injections are possible here", "fix": ""},
    ]
    assert matching_finding(findings, ["injectio"])["description"].startswith("SQL injection")
    assert matching_finding(findings, ["deserial"]) is None

    rows = [
        {"detected": True, "severity_match": True, "secure_flagged": False,
         "secure_any_finding": True, "secure_flagged_high": False,
         "vuln_findings": 2, "secure_findings": 1,
         "severity": "HIGH", "lang": "python", "vuln_latency_ms": 10.0, "secure_latency_ms": 20.0},
        {"detected": False, "severity_match": False, "secure_flagged": True,
         "secure_any_finding": True, "secure_flagged_high": True,
         "vuln_findings": 1, "secure_findings": 3,
         "severity": "HIGH", "lang": "go", "vuln_latency_ms": 30.0, "secure_latency_ms": 40.0},
        {"id": "x", "error": "boom"},
    ]
    summary = aggregate(rows)
    assert summary["overall"]["detection_rate"] == 0.5, summary
    assert summary["overall"]["false_positive_rate"] == 0.5, summary
    assert summary["overall"]["secure_any_finding_rate"] == 1.0, summary
    assert summary["overall"]["severity_match"] == 1.0, summary   # of detections only
    assert summary["errors"] == 1, summary
    print("self-check OK")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the security agent.")
    parser.add_argument("--dataset", default=GOLD_PATH)
    parser.add_argument("--label", default="baseline-rag")
    parser.add_argument("--no-rag", action="store_true", help="ablation: skip retrieval")
    parser.add_argument("--limit", type=int, default=None, help="first N cases, for a smoke run")
    parser.add_argument("--scorer", choices=("judge", "substring"), default="judge",
                        help="judge: LLM grades each finding; substring: technique-word probes")
    parser.add_argument("--self-check", action="store_true", help="scoring tests, no LLM")
    args = parser.parse_args()

    if args.self_check:
        return self_check()

    cases = load_gold(args.dataset)
    if args.limit:
        cases = cases[:args.limit]
    use_rag = not args.no_rag
    scorer = f"judge/{judge.JUDGE_MODEL}" if args.scorer == "judge" else "substring"
    print(f"Loaded {len(cases)} cases | arm={'rag' if use_rag else 'no-rag'} | model={MODEL} | scorer={scorer}")

    results = run(cases, use_rag, args.scorer)
    report = {
        "label": args.label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "arm": "rag" if use_rag else "no-rag",
            "model": MODEL,
            "dataset": os.path.basename(args.dataset),
            "gold_fingerprint": hashlib.sha256(
                open(args.dataset, "rb").read()).hexdigest()[:16],
            "cases": len(cases),
            "excluded_from_retrieval": len(cases),
            "exclusion": "content probes",
            "n_retrieved": 3 if use_rag else 0,
            "scorer": {"detection": scorer, "false_positive": scorer},
        },
        "metrics": aggregate(results),
        "misses": misses(results),
        "results": results,
    }

    print_report(report)
    os.makedirs(REPORT_DIR, exist_ok=True)
   
    safe_label = re.sub(r"[^A-Za-z0-9._-]", "-", args.label)
    out = os.path.join(REPORT_DIR, f"{safe_label}.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n  Report written to {out}\n")


if __name__ == "__main__":
    main()
