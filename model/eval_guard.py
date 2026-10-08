"""Score the adapter on the public TEST splits (never trained on). Usage (from model/): python eval_guard.py . out.json"""
import json, sys, time
from gliner2 import AutoExtractor
ck, out = sys.argv[1], sys.argv[2]
from load_guard import load
m = load(ck)
BARS = (0.5, 0.9)


def p_inj(text):
    got = m.classify_text(text[:3000], {"injection": {"labels": ["injection", "benign"]}}, max_len=400, include_confidence=True)["injection"]
    c = float(got["confidence"])
    return c if got["label"] == "injection" else 1 - c


summary = {"checkpoint": ck, "sets": {}}
for name in ("boundary", "deepset"):
    rows = [json.loads(l) for l in open(f"../data/{name}_test.jsonl") if l.strip()]
    scored, secs = [], []
    for r in rows:
        t = time.time(); p = p_inj(r["text"]); secs.append(time.time() - t)
        scored.append((r["label"], p))
    s = {"n": len(rows), "injections": sum(y for y, _ in scored), "latency_p50_s": round(sorted(secs)[len(secs) // 2], 3)}
    for bar in BARS:
        tp = sum(1 for y, p in scored if y and p >= bar); fp = sum(1 for y, p in scored if not y and p >= bar)
        fn = sum(1 for y, p in scored if y and p < bar); neg = sum(1 for y, _ in scored if not y)
        prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
        s[f"bar{bar}"] = {"precision": round(prec, 3), "recall": round(rec, 3),
                          "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0,
                          "false_flags": round(fp / neg, 3) if neg else 0,
                          "accuracy": round(sum(1 for y, p in scored if (p >= bar) == bool(y)) / len(scored), 3)}
    summary["sets"][name] = s
json.dump(summary, open(out, "w"), indent=1)
print(json.dumps(summary, indent=1))
