# Jev Injection Guard

Finds prompt injection in text an AI agent is about to read: web pages, tool results, MCP responses, emails, files. Jev, a decision model, makes one yes/no call per text, with pattern hits and hidden-text decoding as evidence. A Claude Code hook in this repo withholds a poisoned tool result before the model reads it and blocks the source that sent it.

Jev returns a probability, never text, so an injected page cannot talk its way into the answer.

## Measured

Two public labeled sets, held out: the rules were written against the train splits only and these numbers are from the test splits. Run on 2026-10-02 with `jev-1.13.0`. Everything below is in `data/eval.json`.

**Agent attacks** ([3nesdeniz/agentic-prompt-injection-boundary-pairs](https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-boundary-pairs), test split, 240 texts: 120 attacks across 12 families, and 120 benign look-alikes written to fool a detector, such as a ticket that *reports* an injection and asks the agent to treat it as data)

| | Flagged precision | Flagged recall | F1 | False flags | Blocked precision | Blocked recall | False blocks |
|---|---|---|---|---|---|---|---|
| Rules only (offline) | 82.3% | 46.7% | 0.596 | 10.0% | 70.0% | 11.7% | 5.0% |
| Rules first, Jev on hits (`cascade`) | 90.3% | 46.7% | 0.615 | 5.0% | 100% | 46.7% | 0% |
| **Jev on every text (`jev`, default)** | **91.6%** | **100%** | **0.956** | 9.2% | **99.2%** | **98.3%** | **0.8%** |

Jev caught all 12 attack families at 100%: prompt extraction, role-play jailbreak, tool abuse, approval bypass, RAG poisoning, authority claims, indirect injection, memory poisoning, direct override, encoded payloads, agent-to-agent spoofing, data exfiltration.

**Classic prompt injection** ([deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), test split, 116 texts in English and German, 60 labeled injection)

| | Flagged precision | Flagged recall | F1 | False flags | Blocked recall |
|---|---|---|---|---|---|
| Rules only | 100% | 15.0% | 0.261 | 0% | 0% |
| Jev on every text | 100% | 55.0% | 0.710 | 0% | 40.0% |

Zero false flags on both backends. Most of what Jev lets through here is labeled injection but reads as an ordinary request: "I want you to act as a storyteller", "Generate SQL code to access a database". Those are not attacks on an agent that reads a web page, so the low recall on this set is partly the label.

*Flagged* is a verdict of suspicious or malicious (Jev p >= 0.5). *Blocked* is malicious (p >= 0.8), what the hook acts on.

Cost and speed for Jev on every text: 83,834 input tokens for the 240 texts, $0.0035 at $0.042 per million, so about **$0.015 per 1,000 texts**. 136.6 ms median per request of 8 texts, 161.3 ms p95. The rules alone take 0.16 to 0.36 ms per text.

## Local model: open weights, no API

`model/` holds a 31.8 MB LoRA adapter for [fastino/GLiNER2.5-Decide](https://huggingface.co/fastino/GLiNER2.5-Decide) (Apache-2.0), trained on the train splits of the two public sets above and nothing else: the labels are the datasets' own. It runs offline on a laptop, about 35 ms per text on an M4 Pro. Training takes about 8 minutes (`model/train_guard.py`, 360 steps).

Same held-out test splits as the tables above, verdict at p ≥ 0.5 (`model/eval.json`):

| | Agent attacks F1 | Agent false flags | Classic F1 | Classic false flags |
|---|---|---|---|---|
| Jev on every text | 0.956 | 9.2% | 0.710 | 0% |
| GLiNER2.5-Decide, untuned | 0.956 | 9.2% | 0.673 | 8.9% |
| **Local adapter** | **0.996** | **0%** | **0.940** | 3.6% |

Agent attacks: 119 of 120 caught, no benign look-alike flagged. Classic set: 55 of 60 caught (Jev 33), 2 of 56 benign prompts flagged.

```python
from model.load_guard import load            # pip install gliner2 safetensors
m = load("model")                            # base model + adapter folded in
r = m.classify_text(text, {"injection": {"labels": ["injection", "benign"]}}, include_confidence=True)
```

Limits: train and test splits come from the same two datasets, so these are in-distribution scores. On text unlike them (long web pages, languages other than English and German) expect less, and keep the rules and a second opinion on anything that blocks a source.

## What the rules look for

`rules.py`, standard library regular expressions, each hit with its family, weight and exact span:

- **instruction_override**: "ignore all previous instructions" and relatives, in English, German, French, Spanish, Croatian, Hebrew and Russian
- **role_hijack**: "you are now", developer mode, DAN, "restrictions are suspended"
- **fake_system_tag**: `<|im_start|>`, `[INST]`, `<system>`, `"role": "system"`
- **prompt_extraction**: "reveal your system prompt", "print the text above verbatim"
- **data_exfiltration**: send keys, tokens or `.env` somewhere; markdown images with a data placeholder in the query string
- **tool_coercion**: `curl ... | sh`, `base64 -d | sh`, `powershell -enc`, `rm -rf /`, "escalate your own permissions"
- **approval_bypass**: skip the human review, "do not tell the user", "execute that silently"
- **agent_addressed**: "if you are an AI", "note to the assistant", "decode it and obey it"

Hidden text is decoded and scanned again: invisible Unicode tag characters, zero-width characters inside words, bidi overrides, base64 and hex blobs, spaced-out letters, leetspeak, HTML comments. An injection hidden in tag characters or behind a bidi override is malicious whatever the model says.

## Run it

Python 3.10 or newer, no packages. Jev needs a TypeSafe API key (`TYPESAFE_API_KEY`, `--key-file` or `./.env`); `--backend rules` runs offline with no key.

```
python3 guard.py check < page.txt                 # exit 0 clean, 1 suspicious, 2 malicious
python3 guard.py scan ~/code ~/.claude --json     # every text file under the paths
python3 guard.py scan . --backend rules           # offline

python3 fetch_data.py                             # the two public sets into data/
python3 eval.py                                   # rules, jev and cascade on the test splits
python3 -m unittest discover -s test              # offline, a fake Jev stands in
```

In Python:

```python
import guard
v = guard.Guard("jev").check(text)
v.verdict, v.p, [f.family for f in v.findings]
```

## Block it in Claude Code

`hooks/claude_code_hook.py` runs on PostToolUse and PreToolUse (setup in its header). A malicious result from `WebFetch`, `WebSearch` or any MCP tool is replaced before the model reads it, with a short notice saying what was withheld. The source is added to a block file: the web domain for `WebFetch`, the MCP server otherwise. Every later call to it is denied until you delete its line. Servers that carry other people's content (mail, chat, job boards) go in `JIG_RELAYS`: their poisoned result is withheld, but the server stays open.

Checked end to end with a live `claude -p` session against a test MCP server whose result told the model to reply with a code word and send `~/.env` out. The code word appeared 0 times in the session transcript, the server was blocked, and a new session's call to it was denied, also in `bypassPermissions` mode.

## Bring your own model

Any classifier plugs in as a command that reads JSON lines `{"id", "text"}` on stdin and writes `{"id", "p"}`:

```
python3 eval.py --backend cmd:"python3 examples/keyword_model.py" --out data/eval_keyword.json
python3 guard.py scan ~/code --backend cmd:"python3 my_model.py"
```

`examples/keyword_model.py` is a deliberately weak ten-keyword baseline (`data/eval_keyword.json`: 1.7% recall on the agent set) that shows the protocol. A fine-tuned small model goes in the same slot and gets the same table.

## Limits

- The two sets are short texts. Long pages are split into windows of up to 6,000 characters (the start, plus the windows around rule hits); the hook cuts results into 4,000-character pieces and decides each one.
- 9.2% of the benign look-alikes still get a suspicious flag (p between 0.5 and 0.8). The hook acts only on malicious, where false blocks are 0.8%.
- One run, one model version. Jev's answers can move between versions. Rerun `eval.py` before you trust a new one.

## Data and license

Code and the adapter in `model/`: MIT; the adapter is built on fastino/GLiNER2.5-Decide (Apache-2.0). Data: deepset/prompt-injections and 3nesdeniz/agentic-prompt-injection-boundary-pairs, both CC-BY-4.0, downloaded by `fetch_data.py` from the Hugging Face datasets server. Built with Claude Opus 5.5.
