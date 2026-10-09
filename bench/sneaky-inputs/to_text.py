"""What the agent actually reads, hidden parts included: every text node (display none, white, off-screen, noscript),
comments, alt / aria-label / title / meta content as their own lines. Zero-width and tag characters removed, the way
the repo's rules decode them. MCP JSON: every string value on its own line. Fixed before the second run, not tuned after."""
import json, re
from html.parser import HTMLParser
INVIS = re.compile("[​-‏⁠-⁤﻿\U000e0000-\U000e007f]")
ATTRS = ("alt", "aria-label", "title", "content")

class _P(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.out = []; self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"): self.skip += 1
        for k, v in attrs:
            if k in ATTRS and v and not (tag == "meta" and k == "content" and dict(attrs).get("charset")): self.out.append(v)
    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip: self.skip -= 1
    def handle_data(self, d):
        if not self.skip and d.strip(): self.out.append(d.strip())
    def handle_comment(self, d):
        if d.strip(): self.out.append(d.strip())

def blocks(surface, text):
    text = INVIS.sub("", text)
    if surface == "html":
        p = _P(); p.feed(text); out = p.out
    elif surface == "mcp":
        out = []
        def walk(x):
            if isinstance(x, dict): [walk(v) for v in x.values()]
            elif isinstance(x, list): [walk(v) for v in x]
            elif isinstance(x, str) and x.strip(): out.append(x.strip())
        walk(json.loads(text))
    else:
        out = [l.strip() for l in re.split(r"\n\s*\n", text) if l.strip()]
    return out

def windows(surface, text, size=600):
    wins, cur = [], ""
    for b in blocks(surface, text):
        if cur and len(cur) + len(b) + 1 > size: wins.append(cur); cur = ""
        cur = (cur + "\n" + b).strip()
    if cur: wins.append(cur)
    return wins or [""]
