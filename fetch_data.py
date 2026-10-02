"""Download the two public labeled sets the eval runs on. Standard library only.

    python3 fetch_data.py            # writes data/deepset_{train,test}.jsonl and data/boundary_{train,test}.jsonl

deepset/prompt-injections (CC-BY-4.0): short prompts, label 1 = injection.
3nesdeniz/agentic-prompt-injection-boundary-pairs (CC-BY-4.0): agent-facing texts in matched pairs,
label 1 = injection, label 0 = a benign text built to look like one.
Rows are fetched from the Hugging Face datasets server, 100 at a time.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
API = "https://datasets-server.huggingface.co/rows"
SETS = {
    "deepset": ("deepset/prompt-injections", ("train", "test")),
    "boundary": ("3nesdeniz/agentic-prompt-injection-boundary-pairs", ("train", "test")),
}


def rows(dataset: str, split: str) -> list[dict]:
    out, offset = [], 0
    while True:
        q = urllib.parse.urlencode({"dataset": dataset, "config": "default", "split": split, "offset": offset, "length": 100})
        with urllib.request.urlopen(f"{API}?{q}", timeout=60) as resp:
            page = json.load(resp)
        batch = [r["row"] for r in page["rows"]]
        out += batch
        offset += len(batch)
        if not batch or offset >= page["num_rows_total"]:
            return out
        time.sleep(0.3)


def main() -> None:
    DATA.mkdir(exist_ok=True)
    for name, (dataset, splits) in SETS.items():
        for split in splits:
            got = rows(dataset, split)
            path = DATA / f"{name}_{split}.jsonl"
            with path.open("w", encoding="utf-8") as fh:
                for i, r in enumerate(got):
                    keep = {"id": f"{name}-{split}-{i}", "text": r["text"], "label": int(r["label"])}
                    for extra in ("category", "attack_family", "source_context"):
                        if extra in r:
                            keep[extra] = r[extra]
                    fh.write(json.dumps(keep, ensure_ascii=False) + "\n")
            print(f"{path.name}: {len(got)} rows, {sum(int(r['label']) for r in got)} injections")


if __name__ == "__main__":
    main()
