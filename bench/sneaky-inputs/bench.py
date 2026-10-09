"""Run OpenBles Firewall 1 (the open adapter, as released) on items.jsonl. Usage: python bench.py <model_dir> out.json"""
import json, sys, time, platform
sys.path.insert(0, sys.argv[1])
from load_guard import load
m = load(sys.argv[1])
S = {"injection": {"labels": ["injection", "benign"]}}
WIN, STEP = 1500, 1200

def p_one(t):
    got = m.classify_text(t, S, max_len=400, include_confidence=True)["injection"]
    c = float(got["confidence"]); return c if got["label"] == "injection" else 1 - c

def p_doc(text):
    wins = [text[i:i + WIN] for i in range(0, max(1, len(text) - WIN + STEP), STEP)] or [text]
    return max(p_one(w) for w in wins), len(wins)

items = [json.loads(l) for l in open("items.jsonl")]
p_one(items[0]["text"])  # warm-up, not timed
out = []
for it in items:
    t = time.perf_counter(); p, nw = p_doc(it["text"]); ms = (time.perf_counter() - t) * 1000
    out.append({"id": it["id"], "surface": it["surface"], "trick": it["trick"], "label": it["label"],
                "p": round(p, 4), "flag": p >= 0.5, "windows": nw, "ms": round(ms, 1), "chars": len(it["text"])})
json.dump({"machine": platform.platform(), "items": out}, open(sys.argv[2], "w"), indent=1)
print("done", len(out))
