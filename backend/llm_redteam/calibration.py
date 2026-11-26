"""
Calibration from human review. Each label compares what the SYSTEM reported with what a human decided:
  reported  = the system's final status was "verified"                (it would appear in the report)
  held back = candidate / unstable / needs_review / false_positive    (not reported; includes findings the verifier refuted)
  human     = true_positive | false_positive

  TP = reported & human TP   FP = reported & human FP   FN = held back & human TP   TN = held back & human FP
  precision = TP / (TP + FP)       recall = TP / (TP + FN)

Honest limits: only findings that a human reviewed count, and attempts the judge called "no_violation" never become findings, so recall is measured
against the candidates the system surfaced, not against everything the target could have done wrong. It is an upper bound on true recall.
Nothing here changes behavior by itself: threshold suggestions are shown to a human, who decides whether to apply them.
"""
import math

REPORTED = {"verified"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def _ratio(k: int, n: int):
    return round(k / n, 4) if n else None


def confusion(rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    for r in rows:
        rep, pos = r["system_status"] in REPORTED, r["human"] == "true_positive"
        tp += rep and pos
        fp += rep and not pos
        fn += (not rep) and pos
        tn += (not rep) and not pos
    return {"reviewed": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": _ratio(tp, tp + fp), "precision_ci": wilson(tp, tp + fp),
            "recall": _ratio(tp, tp + fn), "recall_ci": wilson(tp, tp + fn)}


def by_category(rows: list[dict]) -> list[dict]:
    cats: dict[str, list] = {}
    for r in rows:
        cats.setdefault(r.get("category") or "unknown", []).append(r)
    return sorted(({"category": k, **confusion(v)} for k, v in cats.items()), key=lambda x: -x["reviewed"])


def verifier_stats(rows: list[dict]) -> dict:
    """How the adversarial verifier did against the human: refuted & human FP = correct refutation; refuted & human TP = it removed a real finding."""
    ref = [r for r in rows if r.get("verifier") == "refuted"]
    ok = sum(1 for r in ref if r["human"] == "false_positive")
    return {"reviewed_refutations": len(ref), "correct": ok, "wrong": len(ref) - ok, "accuracy": _ratio(ok, len(ref))}


def suggest_threshold(rows: list[dict], target_precision: float = 0.9, min_n: int = 10) -> dict:
    """The lowest judge-confidence cut-off whose reviewed findings above it reach `target_precision` (needs >= min_n labels there). Advice only."""
    pts = [r for r in rows if isinstance(r.get("judge_confidence"), (int, float)) and r["system_status"] in REPORTED | {"false_positive"} | {"candidate", "unstable"}]
    base = {"target_precision": target_precision, "min_n": min_n, "labels": len(pts)}
    if len(pts) < min_n:
        return base | {"threshold": None, "reason": f"need at least {min_n} reviewed findings with a judge confidence (have {len(pts)})"}
    for t in [x / 100 for x in range(50, 100, 5)]:
        sel = [r for r in pts if r["judge_confidence"] >= t]
        if len(sel) < min_n:
            break
        tp = sum(r["human"] == "true_positive" for r in sel)
        if tp / len(sel) >= target_precision:
            return base | {"threshold": t, "n": len(sel), "precision": round(tp / len(sel), 4), "reason": f"findings with judge confidence ≥ {t:.2f} were {round(100 * tp / len(sel))}% true positives"}
    return base | {"threshold": None, "reason": f"no confidence cut-off reached {round(100 * target_precision)}% precision with at least {min_n} labels"}


def summary(rows: list[dict]) -> dict:
    return {**confusion(rows), "by_category": by_category(rows), "verifier": verifier_stats(rows), "threshold": suggest_threshold(rows),
            "note": "Recall is measured only over candidates the system surfaced; attempts judged as no violation are not reviewed, so true recall can be lower."}
