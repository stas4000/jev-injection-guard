"""Jev Injection Guard: find prompt injection in text an AI agent is about to read.

    python3 guard.py check < page.txt                       # one text from stdin
    python3 guard.py scan ~/code ~/.claude --json > out.json # every text file under the paths
    python3 guard.py scan . --backend rules                  # no network, no key

Backends:
    jev       Jev decides every text (jev.py), rule hits ride along as evidence (the default: data/eval.json)
    rules     pattern families and hidden-text decoding only (rules.py), offline
    cascade   rules first; Jev decides only texts the rules flagged (cheapest, misses what the rules miss)
    cmd:CMD   your own model: CMD reads JSON lines {"id","text"} on stdin and writes {"id","p"} lines

A verdict is clean, suspicious or malicious. Hidden payloads (invisible Unicode tag text, a bidi
override) carrying an injection are malicious whatever the model says.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import jev  # noqa: E402
import rules  # noqa: E402

MALICIOUS_P = 0.8
SUSPICIOUS_P = 0.5
WINDOWS = 4          # Jev windows per long text: the start plus the regions around rule hits
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", ".cache", "site-packages"}
MAX_FILE = 2_000_000


@dataclass
class Verdict:
    verdict: str                 # clean | suspicious | malicious
    p: float | None              # model probability of injection, None when no model ran
    score: float                 # rules score
    findings: list = field(default_factory=list)
    backend: str = "rules"

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "p": self.p, "score": self.score, "backend": self.backend,
                "findings": [f.as_dict() for f in self.findings]}


def _from_p(p: float) -> str:
    return "malicious" if p >= MALICIOUS_P else "suspicious" if p >= SUSPICIOUS_P else "clean"


def _critical(findings: list) -> bool:
    return any(f.layer in rules.CRITICAL_LAYERS and f.family != "hidden_text" for f in findings)


def windows(text: str, findings: list) -> list[str]:
    """The text itself when it fits, else its start and the windows around the first rule hits."""
    if len(text) <= jev.MAX_CHARS:
        return [text]
    half = jev.MAX_CHARS // 2
    starts = [0] + [max(0, f.start - half) for f in sorted(findings, key=lambda f: -f.weight)]
    out, seen = [], set()
    for s in starts:
        key = s // half
        if key not in seen:
            seen.add(key)
            out.append(text[s:s + jev.MAX_CHARS])
        if len(out) >= WINDOWS:
            break
    return out


class Guard:
    """Holds a backend and turns texts into verdicts. usage collects every Jev request's usage."""

    def __init__(self, backend: str = "jev", ask: jev.Ask | None = None):
        if backend not in ("rules", "jev", "cascade") and not backend.startswith("cmd:"):
            raise ValueError(f"unknown backend {backend!r}")
        self.backend = backend
        self.ask = ask
        self.usage: list[dict] = []

    def _model_p(self, items: list[tuple[str, list]]) -> list[float]:
        """Max window probability per text."""
        if self.backend.startswith("cmd:"):
            return cmd_probabilities(self.backend[4:], [t for t, _ in items])
        if self.ask is None:
            self.ask = jev.http_ask(jev.load_key())
        flat, owner, hints = [], [], []
        for i, (text, findings) in enumerate(items):
            hint = sorted({f"{f.family} ({f.layer})" for f in findings})
            for w in windows(text, findings):
                flat.append(w)
                owner.append(i)
                hints.append(hint)
        probs, usage = jev.probabilities(self.ask, flat, hints)
        self.usage += usage
        best = [0.0] * len(items)
        for i, p in zip(owner, probs):
            best[i] = max(best[i], p)
        return best

    def check_many(self, texts: list[str]) -> list[Verdict]:
        found = [rules.scan(t) for t in texts]
        out = [Verdict(*rules.verdict(f)[:1], None, rules.score(f), f, "rules") for f in found]
        if self.backend == "rules":
            return out
        todo = [i for i, f in enumerate(found) if self.backend != "cascade" or f]
        if not todo:
            return out
        probs = self._model_p([(texts[i], found[i]) for i in todo])
        for i, p in zip(todo, probs):
            v = "malicious" if _critical(found[i]) else _from_p(p)
            out[i] = Verdict(v, p, rules.score(found[i]), found[i], self.backend)
        return out

    def check(self, text: str) -> Verdict:
        return self.check_many([text])[0]


def cmd_probabilities(command: str, texts: list[str]) -> list[float]:
    """Run your own model once over all texts: JSON lines in, JSON lines with "p" out, matched by id."""
    payload = "".join(json.dumps({"id": i, "text": t}, ensure_ascii=False) + "\n" for i, t in enumerate(texts))
    proc = subprocess.run(shlex.split(command), input=payload, capture_output=True, text=True, timeout=3600)
    if proc.returncode:
        raise RuntimeError(f"model command failed ({proc.returncode}): {proc.stderr[-400:]}")
    got = {}
    for line in proc.stdout.splitlines():
        if line.strip():
            row = json.loads(line)
            got[int(row["id"])] = float(row["p"])
    missing = [i for i in range(len(texts)) if i not in got]
    if missing:
        raise RuntimeError(f"model command returned no p for {len(missing)} texts (first id {missing[0]})")
    return [got[i] for i in range(len(texts))]


# ----------------------------------------------------------------------------------------- scanning files

def iter_files(paths: list[str]):
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            yield p
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                yield Path(dirpath) / name


def read_text(path: Path) -> str | None:
    try:
        if path.is_symlink() or path.stat().st_size > MAX_FILE:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_paths(guard: Guard, paths: list[str], min_level: str = "suspicious") -> dict:
    """Rules over every text file, the model over the flagged ones. Returns totals and the flagged files."""
    started = time.perf_counter()
    files = texts = 0
    flagged_paths, flagged_texts = [], []
    for path in iter_files(paths):
        files += 1
        text = read_text(path)
        if text is None:
            continue
        texts += 1
        if guard.backend == "cascade" and not rules.scan(text):
            continue
        flagged_paths.append(path)
        flagged_texts.append(text)
    verdicts = guard.check_many(flagged_texts) if flagged_texts else []
    order = {"clean": 0, "suspicious": 1, "malicious": 2}
    results = []
    for path, text, v in zip(flagged_paths, flagged_texts, verdicts):
        if order[v.verdict] < order[min_level]:
            continue
        row = v.as_dict()
        row["path"] = str(path)
        for f in row["findings"]:
            f["line"] = line_of(text, f["start"]) if f["layer"] != "leet" else None
        results.append(row)
    results.sort(key=lambda r: (-order[r["verdict"]], -(r["p"] or 0), r["path"]))
    return {"files_seen": files, "text_files": texts, "rule_hits": len(flagged_texts),
            "flagged": len(results), "malicious": sum(r["verdict"] == "malicious" for r in results),
            "seconds": round(time.perf_counter() - started, 2), "jev_requests": len(guard.usage),
            "jev_input_tokens": sum(int(u.get("input_tokens") or 0) for u in guard.usage), "results": results}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find prompt injection in text an AI agent is about to read.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="one text from stdin; exit 2 when malicious, 1 when suspicious")
    c.add_argument("--backend", default="jev")
    c.add_argument("--key-file")
    s = sub.add_parser("scan", help="every text file under the given paths")
    s.add_argument("paths", nargs="+")
    s.add_argument("--backend", default="jev")
    s.add_argument("--key-file")
    s.add_argument("--min", default="suspicious", choices=("suspicious", "malicious"))
    s.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ask = None
    if a.backend in ("jev", "cascade"):
        ask = jev.http_ask(jev.load_key(a.key_file))
    guard = Guard(a.backend, ask)
    if a.cmd == "check":
        v = guard.check(sys.stdin.read())
        print(json.dumps(v.as_dict(), ensure_ascii=False, indent=2))
        return {"clean": 0, "suspicious": 1, "malicious": 2}[v.verdict]
    report = scan_paths(guard, a.paths, a.min)
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for r in report["results"]:
            f = r["findings"][0] if r["findings"] else {}
            p = "" if r["p"] is None else f" p={r['p']:.2f}"
            print(f"{r['verdict']:<10}{p}  {r['path']}:{f.get('line') or ''}  {f.get('family', '')}: {f.get('evidence', '')[:70]!r}")
        print(f"\n{report['text_files']} text files, {report['rule_hits']} with rule hits, "
              f"{report['flagged']} flagged, {report['malicious']} malicious, {report['seconds']} s")
    return 2 if report["malicious"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
