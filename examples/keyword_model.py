"""The smallest possible "your own model" for the cmd: backend: JSON lines {"id","text"} in, {"id","p"} out.

    python3 eval.py --backend cmd:"python3 examples/keyword_model.py" --out data/eval_keyword.json

Swap the body of p() for your trained classifier (a fine-tuned small model, a local server call).
"""
import json
import sys

WORDS = ("ignore previous", "ignore all previous", "ignore prior", "system prompt", "disregard", "jailbreak",
         "bypass", "without approval", "you are now", "developer mode")


def p(text: str) -> float:
    t = text.lower()
    hits = sum(w in t for w in WORDS)
    return min(1.0, 0.45 * hits)


for line in sys.stdin:
    if line.strip():
        row = json.loads(line)
        print(json.dumps({"id": row["id"], "p": p(row["text"])}))
