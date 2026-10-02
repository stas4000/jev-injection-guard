"""Measure every backend on the held-out test splits and write data/eval.json.

    python3 fetch_data.py
    python3 eval.py                                   # rules, jev, cascade
    python3 eval.py --backend cmd:"python3 my_model.py" --out data/eval_mine.json

A text counts as flagged when its verdict is suspicious or malicious, and as blocked when it is
malicious (what an agent hook would cut off). Train splits are never read here: the rules were
written against the train splits only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import guard  # noqa: E402
import jev  # noqa: E402

DATA = ROOT / "data"
SETS = ("deepset_test", "boundary_test")
PRICE_PER_MTOK = 0.042  # TypeSafe input-token price used for the cost column


def metrics(labels: list[int], preds: list[bool]) -> dict:
    tp = sum(1 for y, p in zip(labels, preds) if y and p)
    fp = sum(1 for y, p in zip(labels, preds) if not y and p)
    fn = sum(1 for y, p in zip(labels, preds) if y and not p)
    tn = sum(1 for y, p in zip(labels, preds) if not y and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "accuracy": round((tp + tn) / len(labels), 4)}


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return round(s[min(len(s) - 1, int(round(q * (len(s) - 1))))], 4) if s else 0.0


def run(backend: str, rows: list[dict], ask) -> dict:
    g = guard.Guard(backend, ask)
    started = time.perf_counter()
    verdicts = g.check_many([r["text"] for r in rows])
    took = time.perf_counter() - started
    labels = [r["label"] for r in rows]
    out = {
        "n": len(rows), "positives": sum(labels),
        "flagged": metrics(labels, [v.verdict != "clean" for v in verdicts]),
        "blocked": metrics(labels, [v.verdict == "malicious" for v in verdicts]),
        "seconds_total": round(took, 3),
        "ms_per_text": round(1000 * took / len(rows), 3),
    }
    if g.usage:
        tokens = sum(int(u.get("input_tokens") or 0) for u in g.usage)
        secs = [u["seconds"] for u in g.usage if "seconds" in u]
        out["jev"] = {"requests": len(g.usage), "texts_sent": sum(v.p is not None for v in verdicts),
                      "input_tokens": tokens, "cost_usd": round(tokens * PRICE_PER_MTOK / 1e6, 6),
                      "request_ms_median": round(1000 * pct(secs, 0.5), 1), "request_ms_p95": round(1000 * pct(secs, 0.95), 1),
                      "model": next((u.get("model") for u in g.usage if u.get("model")), None)}
    fam = defaultdict(lambda: [0, 0])
    for r, v in zip(rows, verdicts):
        if r["label"] and r.get("attack_family"):
            fam[r["attack_family"]][0] += v.verdict != "clean"
            fam[r["attack_family"]][1] += 1
    if fam:
        out["recall_by_family"] = {k: round(a / b, 3) for k, (a, b) in sorted(fam.items())}
    out["rows"] = [{"id": r["id"], "label": r["label"], "verdict": v.verdict, "p": v.p, "score": v.score}
                   for r, v in zip(rows, verdicts)]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", action="append", help="repeatable; default rules, jev and cascade")
    ap.add_argument("--key-file")
    ap.add_argument("--out", default=str(DATA / "eval.json"))
    a = ap.parse_args()
    backends = a.backend or ["rules", "jev", "cascade"]
    ask = jev.http_ask(jev.load_key(a.key_file)) if any(b in ("jev", "cascade") for b in backends) else None
    result = {"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "thresholds": {"malicious_p": guard.MALICIOUS_P, "suspicious_p": guard.SUSPICIOUS_P},
              "datasets": {}}
    for name in SETS:
        rows = [json.loads(line) for line in (DATA / f"{name}.jsonl").read_text().splitlines() if line.strip()]
        result["datasets"][name] = {}
        for b in backends:
            res = run(b, rows, ask)
            result["datasets"][name][b] = res
            f = res["flagged"]
            print(f"{name:<15} {b:<10} n={res['n']} P={f['precision']:.3f} R={f['recall']:.3f} F1={f['f1']:.3f} "
                  f"FPR={f['false_positive_rate']:.3f}" + (f"  jev tokens={res['jev']['input_tokens']} ${res['jev']['cost_usd']}" if "jev" in res else ""))
    Path(a.out).write_text(json.dumps(result, indent=1) + "\n")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
