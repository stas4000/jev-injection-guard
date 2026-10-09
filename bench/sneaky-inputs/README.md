# Sneaky inputs: hidden HTML, poisoned MCP results, poisoned skills

One run of OpenBles Firewall 1 (the released adapter, unchanged) on 164 inputs we wrote, 9 Oct 2026, MacBook Pro M5. Every attack has a clean twin hidden the same way, so a model that simply flags hidden text scores badly.

- 60 web pages with an injection hidden 10 ways: `display:none`, white on white, `font-size:0`, off screen, HTML comment, `alt`, `aria-label` and `title`, `<meta>`, zero width characters, `<noscript>`. 64 clean pages: 60 that use the same 10 tricks for ordinary content (cookie notes, SEO text, skip links) and 4 look-alikes that talk about prompt injection.
- 12 MCP tool results (email, issues, search, chat, database rows, tickets) with an injection in a field, 6 clean ones.
- 12 poisoned `SKILL.md` files, 10 clean ones.

## Results

Verdict at p of 0.5 or more. A long input is cut into windows and flagged when any window is.

| What the model is fed | Hidden HTML attacks caught | Clean pages flagged | MCP caught | MCP clean flagged | Skills caught | Clean skills flagged | ms per input, median |
|---|---|---|---|---|---|---|---|
| Raw markup (`bench.py`) | 58 of 60 | 56 of 64 | 8 of 12 | 4 of 6 | 10 of 12 | 8 of 10 | 131 |
| Text the agent reads, hidden parts included (`bench2.py`, `to_text.py`) | **60 of 60** | 28 of 64 | **12 of 12** | 1 of 6 | 9 of 12 | 8 of 10 | **65** |

What this says:

- Feed it text, not markup. `to_text.py` keeps every hidden text node, comment and `alt`/`aria-label`/`title`/`meta` value, and strips zero width characters. That is what an agent reads, and it is where the model works.
- Every hidden HTML attack and every poisoned tool result was caught.
- Clean full pages and clean skills still get flagged too often. Firewall 1 learned on short texts, and a skill is instructions by design. Both need training on that shape of text.

## Rerun

```
python3 make_set.py                  # writes items.jsonl
python3 bench2.py ../../model out.json   # pip install gliner2 safetensors
```

`summarize.py` turns `results_raw.json` and `results_text.json` into `results.json`.
