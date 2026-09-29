"""Paired comparison of two judged reports over the same cases.

    python -m evals.compare evals/reports/BEFORE-judged.json evals/reports/AFTER-judged.json

Only cases both reports scored are compared, and only cases whose verdict changed
carry information - McNemar's exact test on those discordant pairs.
"""
import argparse
import json
from math import comb


def load(path: str) -> dict[str, dict]:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    return {r["id"]: r for r in report["results"] if not r.get("error")}


def paired(before: dict, after: dict, field: str) -> dict:
    """McNemar's exact test on one boolean field of the results."""
    ids = sorted(set(before) & set(after))
    gained = sum(after[i][field] and not before[i][field] for i in ids)   # became True
    lost = sum(before[i][field] and not after[i][field] for i in ids)     # became False
    n = gained + lost
    p = min(1.0, 2 * sum(comb(n, k) for k in range(min(gained, lost) + 1)) / 2 ** n) if n else 1.0
    return {
        "cases": len(ids),
        "before": sum(before[i][field] for i in ids) / len(ids),
        "after": sum(after[i][field] for i in ids) / len(ids),
        "gained": gained,
        "lost": lost,
        "p": p,
    }


# Fixed before the gold result of the evidence change was read. Moving them after
# reading a result turns a test into a description of it.
MAX_DETECTION_LOSS = 1  # net cases; a missed vulnerability costs more than a false alarm
MIN_FP_REDUCTION = 3    # net cases; a swing of one or two is within the judge's error (kappa 0.72)


def accept(detection: dict, false_positives: dict) -> tuple[bool, str]:
    """Does the change ship? Decided before the result is seen, so the bar cannot
    move to fit it. Returns (ship, one-line reason).

    Non-inferiority, not significance: at n = 40 almost no real change reaches
    p < 0.05, so p is reported but does not decide.
    """
    detection_loss = detection["lost"] - detection["gained"]
    # For false positives "lost" is the good direction: a fixed snippet no longer flagged.
    fp_reduction = false_positives["lost"] - false_positives["gained"]

    if detection_loss > MAX_DETECTION_LOSS:
        return False, f"detection fell by {detection_loss} cases net (tolerance {MAX_DETECTION_LOSS})"
    if fp_reduction < MIN_FP_REDUCTION:
        return False, f"false positives fell by {fp_reduction} cases net (needs {MIN_FP_REDUCTION})"
    return True, (f"false positives {false_positives['before']:.3f} -> {false_positives['after']:.3f} "
                  f"({fp_reduction} cases net, p={false_positives['p']:.2f}); detection "
                  f"{detection['before']:.3f} -> {detection['after']:.3f}, within tolerance")


def _self_check() -> None:
    """The sign of 'lost' flips between the two metrics; a swap would invert verdicts."""
    d = lambda gained, lost: {"gained": gained, "lost": lost, "before": 0.8, "after": 0.8, "p": 1.0}
    assert accept(d(0, 0), d(0, 3))[0], "3 false positives cleared, no detection change: ship"
    assert not accept(d(0, 2), d(0, 9))[0], "2 detections lost outweighs any false-positive gain"
    assert not accept(d(0, 0), d(3, 5))[0], "net 2 false positives cleared is not enough"
    assert not accept(d(0, 0), d(3, 0))[0], "new false positives are not an improvement"
    print("self-check OK")


def main() -> None:
    parser = argparse.ArgumentParser(description="Paired comparison of two judged reports.")
    parser.add_argument("before", nargs="?")
    parser.add_argument("after", nargs="?")
    parser.add_argument("--self-check", action="store_true", help="test the acceptance rule")
    args = parser.parse_args()
    if args.self_check:
        return _self_check()
    if not (args.before and args.after):
        parser.error("give two judged reports, or --self-check")

    before, after = load(args.before), load(args.after)
    detection = paired(before, after, "detected")
    false_positives = paired(before, after, "secure_flagged")

    print(f"\n  {detection['cases']} paired cases")
    for label, r in (("detection", detection), ("false positives", false_positives)):
        print(f"  {label:<16} {r['before']:.3f} -> {r['after']:.3f}"
              f"   became True {r['gained']}, became False {r['lost']}, McNemar p={r['p']:.3f}")

    ship, reason = accept(detection, false_positives)
    print(f"\n  {'SHIP' if ship else 'DO NOT SHIP'}: {reason}\n")


if __name__ == "__main__":
    main()
