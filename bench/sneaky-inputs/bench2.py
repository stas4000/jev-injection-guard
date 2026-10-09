"""Second run: classify what the agent reads (to_text.windows), page flagged when any window is. Usage: python bench2.py <model_dir> out.json"""
import json, sys, time, platform
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, ".")
from load_guard import load
import to_text
m = load(sys.argv[1])
S = {"injection": {"labels": ["injection", "benign"]}}
def p_one(t):
    got = m.classify_text(t, S, max_len=400, include_confidence=True)["injection"]
    c = float(got["confidence"]); return c if got["label"] == "injection" else 1 - c
items = [json.loads(l) for l in open("items.jsonl")]
p_one("warm up")
out = []
for it in items:
    t = time.perf_counter(); wins = to_text.windows(it["surface"], it["text"]); ps = [p_one(w) for w in wins]
    ms = (time.perf_counter() - t) * 1000
    out.append({"id": it["id"], "surface": it["surface"], "trick": it["trick"], "label": it["label"], "p": round(max(ps), 4),
                "flag": max(ps) >= 0.5, "windows": len(wins), "ms": round(ms, 1), "chars": len(it["text"])})
json.dump({"machine": platform.platform(), "mode": "text", "items": out}, open(sys.argv[2], "w"), indent=1)
print("done", len(out))
