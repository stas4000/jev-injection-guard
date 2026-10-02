"""Deterministic first pass: pattern families of LLM prompt injection, plus text hidden from a human reader.

No model, no network, a few milliseconds per page. Every finding names its family, a weight and the
exact span, so a person (or Jev, which gets the findings as evidence) can see why a text was flagged.

Hidden text is decoded and scanned again: Unicode tag characters (invisible ASCII), zero-width
separators inside words, spaced-out letters, leetspeak, and base64 or hex blobs that decode to text.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, asdict

# A verdict from the rules alone. "critical" families are malicious on their own.
MALICIOUS_AT = 3.0
SUSPICIOUS_AT = 1.5


@dataclass(frozen=True)
class Finding:
    family: str
    weight: float
    start: int
    end: int
    evidence: str
    layer: str = "plain"  # plain, or the decoding that revealed it (tags, base64, hex, spaced, leet)

    def as_dict(self) -> dict:
        return asdict(self)


def _rx(*parts: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE | re.DOTALL)


_PRIOR = r"(?:all|any|every|the|your|my|these|those|its)?\s*(?:(?:assistant|model|ai|agent|bot)'?s\s+)?(?:previous|prior|preceding|earlier|above|former|original|initial|system|developer|existing|current|safety|other)?"
_ORDERS = r"(?:instructions?|prompts?|rules?|directions?|guidelines?|orders|context|constraints|polic(?:y|ies)|restrictions|guardrails|messages?|conversation)"

FAMILIES: dict[str, tuple[float, re.Pattern]] = {
    # "ignore all previous instructions" and its relatives, in the languages the public sets use.
    "instruction_override": (2.5, _rx(
        rf"\b(?:ignore|disregard|forget|override|overrule|bypass|skip|drop|abandon|discard|neglect)\s+(?:about\s+)?{_PRIOR}\s*{_ORDERS}",
        r"\b(?:forget|ignore|disregard)\s+(?:about\s+)?(?:everything|all\s+(?:of\s+)?(?:that|this|the\s+above)|what\s+(?:i|you)\s+(?:said|were\s+told))",
        rf"\b(?:{_ORDERS})\s+(?:above|before|so\s+far)\s+(?:are|is)\s+(?:void|cancel+ed|irrelevant|obsolete|no\s+longer\s+valid)",
        r"\bno\s+longer\s+(?:bound|restricted)\s+by\b",
        r"\b(?:the\s+)?(?:current|previous|old|existing)\s+(?:policy|rules?|instructions?)\s+(?:no\s+longer|do(?:es)?\s+not)\s+apply",
        r"\bnew\s+(?:system\s+)?instructions?\s*[:\-]",
        r"\btreat\s+this\s+as\s+(?:the\s+)?(?:highest|top)[-\s]priority\s+instruction",
        r"\b(?:highest|top)[-\s]priority\s+(?:instruction|override|directive)",
        r"\binstead\s*,?\s+(?:just\s+)?(?:say|print|write|output|respond\s+with)\b",
        # German, French, Spanish, Croatian, Hebrew, Russian
        r"\b(?:vergiss|vergessen\s+sie|ignorier(?:e|en\s+sie)?)\s+(?:alles|alle|die\s+vorherigen|bisherigen)",
        r"\balle\s+(?:bisherigen|vorherigen)\s+(?:informationen|anweisungen|instruktionen)",
        r"\b(?:oubliez|oublie|ignorez|ignore)\s+(?:toutes?\s+les|les)\s+(?:instructions|consignes|r[eè]gles)",
        r"\b(?:olvida|ignora)\s+(?:todas?\s+las|las)\s+(?:instrucciones|reglas)",
        r"\bzaboravi\s+sve",
        r"(?:התעלם|תתעלם|שכח|תשכח|התעלמי|שכחי)\s+(?:מ)?(?:כל\s+)?(?:ה)?(?:הוראות|הנחיות|כללים|מה\s+שנאמר)",
        r"(?:игнорируй|забудь|проигнорируй)\s+(?:все\s+)?(?:предыдущие\s+)?(?:инструкции|указания|правила)",
    )),
    # "you are now DAN", developer mode, the safety-off role play.
    "role_hijack": (2.0, _rx(
        r"\byou\s+are\s+(?:now|no\s+longer)\b",
        r"\bfrom\s+now\s+on\s*,?\s+you\s+(?:are|will|must|shall|act)",
        r"\b(?:act|behave|pretend|roleplay|role-play)\s+(?:as\s+if\s+you\s+(?:are|were)|as|to\s+be)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|rogue|different)",
        r"\b(?:developer|god|admin|sudo|jailbreak|unrestricted|dan)\s+mode\b",
        r"\bdo\s+anything\s+now\b",
        r"\bjailbr(?:eak|oken)\b",
        r"\b(?:normal|usual|all|your)\s+(?:restrictions|rules|safeguards|filters|guardrails)\s+(?:are|have\s+been)\s+(?:suspended|lifted|removed|disabled|off)",
        r"\bwithout\s+(?:any\s+)?(?:restrictions|filters|censorship|limitations|guardrails)\b",
        r"\bdu\s+bist\s+(?:jetzt|nun|kein)\b",
        r"\bתהיה\s+עכשיו\b|\bאתה\s+עכשיו\b",
    )),
    # Chat-template and system markers that only a model reads.
    "fake_system_tag": (2.5, _rx(
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|eot_id)\|>",
        r"\[/?INST\]|<<\s*/?SYS\s*>>",
        r"</?\s*(?:system|system_prompt|sys|admin|instructions?|developer)\s*>",
        r"^\s*#{2,}\s*(?:system|instruction|admin)\s*(?:prompt|message|override)?\s*:?\s*$",
        r"\b(?:begin|start|end)\s+(?:of\s+)?(?:system|hidden|secret)\s+(?:prompt|instructions?|message)\b",
        r"[\"']role[\"']\s*:\s*[\"']system[\"']",
        r"^\s*(?:system|assistant)\s*:\s*\S",
    )),
    # Asking the model to hand over its own prompt.
    "prompt_extraction": (2.5, _rx(
        r"\b(?:reveal|print|show|repeat|output|display|disclose|tell\s+me|give\s+me|write\s+out|dump|leak|recite)\s+(?:me\s+)?(?:all\s+of\s+)?(?:your|the|its)\s+(?:full\s+|entire\s+|complete\s+|exact\s+|private\s+|hidden\s+|original\s+|initial\s+|secret\s+)*(?:system\s+prompt|prompt|instructions|initial\s+instructions|hidden\s+instructions|configuration|rules)",
        r"\b(?:what|which)\s+(?:is|are|were)\s+your\s+(?:system\s+prompt|(?:initial|original|hidden)\s+instructions)",
        r"\bverbatim\b.{0,40}\b(?:prompt|instructions)\b|\b(?:prompt|instructions)\b.{0,40}\bverbatim\b",
        r"\btext\s+above\s+(?:this|starting)\b",
    )),
    # Moving secrets or private data out.
    "data_exfiltration": (2.5, _rx(
        r"\b(?:send|post|upload|exfiltrate|forward|email|e-mail|transmit|leak|share|paste|copy)\b.{0,80}\b(?:api[\s_-]?keys?|tokens?|passwords?|credentials?|secrets?|\.env\b|ssh\s+keys?|private\s+keys?|cookies|session\s+ids?|card\s+numbers?)",
        r"\b(?:api[\s_-]?keys?|tokens?|passwords?|credentials?|secrets?|\.env\b|ssh\s+keys?|cookies)\b.{0,60}\b(?:to|at)\s+(?:https?://|\S+@\S+\.\w+)",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=(?:\{|\$|%7b|<|\[)",
        r"\b(?:extract|collect|gather|dump)\s+(?:every|all)\s+(?:secrets?|credentials?|passwords?|tokens?|personal\s+records?|hidden\s+values?)",
        r"\bwithout\s+(?:masking|redact(?:ing|ion)|summari[sz]ing)\b",
        r"\bcat\s+(?:~|/home|/root|/etc)[^\s]*/(?:\.env|\.ssh|id_rsa|shadow|\.aws|credentials)",
    )),
    # Pushing an agent to run code or a destructive action.
    "tool_coercion": (2.5, _rx(
        r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
        r"\bbase64\s+(?:-d|--decode)\b[^\n]{0,40}\|\s*(?:ba)?sh\b",
        r"\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:odedcommand)?)?\s+[a-z0-9+/=]{20,}",
        r"\brm\s+-[a-z]*r[a-z]*f?\s+(?:--no-preserve-root\s+)?(?:/|~|\$home)(?:\s|$)",
        r"\b(?:run|execute|eval)\s+(?:the\s+)?(?:following|this)\s+(?:shell\s+)?(?:command|code|script)\b",
        r"\bescalate\s+(?:your|its)\s+(?:own\s+)?(?:permissions|privileges|access)",
        r"\b(?:even\s+if|although)\s+(?:the\s+operation\s+is\s+|it\s+is\s+)?(?:marked\s+)?(?:destructive|irreversible)",
        r"\bdeploy\s+(?:the\s+)?unreviewed\b",
    )),
    # Skipping the human, hiding the act.
    "approval_bypass": (2.0, _rx(
        r"\b(?:bypass|skip|circumvent|avoid|disable|ignore)\s+(?:the\s+)?(?:human|manual|two-person|second|owner|user|admin)?[-\s]?(?:in-the-loop\s+)?(?:approval|review|confirmation|verification|sign-?off|check)s?\b",
        r"\bwithout\s+(?:asking|consulting|telling|notifying|informing|confirmation|approval|the\s+user'?s?\s+(?:knowledge|consent|approval))",
        r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|mention\s+(?:this|it)\s+to)\s+(?:the\s+)?(?:user|owner|human|operator|admin)",
        r"\b(?:execute|do|perform|run)\s+(?:that|this|it)\s+(?:instruction\s+)?silently\b",
        r"\blabel\s+(?:the\s+)?result\s+['\"]?approved",
        r"\bnever\s+verify\s+(?:it|this|me)\s+again\b",
        r"\bbefore\s+anyone\s+(?:else\s+)?(?:can|could)\s+(?:review|notice|check)",
        r"\baccept\s+(?:the|this|that|their)\s+claim\s+without\s+verif",
        r"\b(?:do\s+not|don'?t|never)\s+ask\s+(?:for\s+)?(?:proof|verification|confirmation|approval)",
        r"\bfalsely\s+(?:record|mark|report|label)\b",
        r"\bretry\s+with\s+(?:a\s+)?(?:broader|higher|elevated|admin)\s+(?:role|permissions?|privileges?)",
    )),
    # Text written to whatever AI reads it, rather than to a person.
    "agent_addressed": (1.5, _rx(
        r"\b(?:if|when)\s+you\s+are\s+an?\s+(?:ai|llm|large\s+language\s+model|language\s+model|assistant|chatbot|agent|bot)\b",
        r"\b(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:ai|llm|assistant|agent|model|chatbot|language\s+model)s?\b",
        r"\b(?:ai|llm)\s+(?:agents?|assistants?|models?)\s+(?:reading|processing|summari[sz]ing)\s+this\b",
        r"\b(?:important|attention|urgent)\s*[:!]\s*(?:ai|assistant|agent|llm|model)s?\b",
        r"\btreat\s+any\s+instruction\s+addressed\s+to\s+the\s+ai\s+as\s+authoritative",
        r"\b(?:decode|translate)\s+(?:it|this)\s+and\s+(?:obey|follow|execute)\b",
        r"\b(?:obey|follow|execute)\s+(?:it|them|this)\s+as\s+(?:a\s+)?(?:private|hidden|secret)\s+instruction",
        r"\bit\s+is\s+trusted\s+because\b|\bits\s+embedded\s+authorization\b",
        r"\bfollow\s+the\s+(?:embedded|hidden|included|enclosed)\s+instructions?\b",
        r"\bpromote\s+(?:that|this|the)\s+\w+\s+to\s+(?:a\s+)?system\s+(?:instruction|prompt|message)",
        r"\btreat\s+(?:it|this|them)\s+as\s+(?:the\s+)?(?:governing|new|binding|official)\s+(?:policy|instructions?|rules?)",
        r"\b(?:outranks|supersedes|overrides)\s+(?:the\s+)?(?:user|system|operator|owner)",
    )),
}

# Families heavy enough that one hit plus any second signal is malicious.
CRITICAL_LAYERS = {"tags", "bidi"}

_TAG_RE = re.compile("[\U000E0000-\U000E007F]+")
_ZW_RE = re.compile("[​‌‍⁠﻿]")
_BIDI_RE = re.compile("[‪-‮⁦-⁩]")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_SPACED_RE = re.compile(r"(?:\b[a-zA-Z]\s){8,}[a-zA-Z]\b")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    letters = sum(c.isalpha() or c.isspace() for c in text)
    return text if text and letters / len(text) > 0.85 else None


def _layers(text: str) -> list[tuple[str, int, str]]:
    """(layer, offset in the original, decoded text) for every hidden layer worth scanning again."""
    out: list[tuple[str, int, str]] = []
    for m in _TAG_RE.finditer(text):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        if decoded.strip():
            out.append(("tags", m.start(), decoded))
    for m in _B64_RE.finditer(text):
        blob = m.group()
        try:
            decoded = _printable(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False))
        except (binascii.Error, ValueError):
            decoded = None
        if decoded:
            out.append(("base64", m.start(), decoded))
    for m in _HEX_RE.finditer(text):
        decoded = _printable(bytes.fromhex(m.group()))
        if decoded:
            out.append(("hex", m.start(), decoded))
    for m in _SPACED_RE.finditer(text):
        out.append(("spaced", m.start(), re.sub(r"(?<=\w)\s(?=\w)", "", m.group())))
    # "i g n o r e   p r i o r" keeps double spaces between words
    for m in re.finditer(r"(?:\b[a-zA-Z] ){3,}[a-zA-Z](?:\s{2,3}(?:[a-zA-Z] ){1,}[a-zA-Z])+", text):
        words = [w.replace(" ", "") for w in re.split(r"\s{2,3}", m.group())]
        out.append(("spaced", m.start(), " ".join(words)))
    if re.search(r"[a-z][0-9@$][a-z]|[0-9][a-z]{2}", text, re.I):
        leet = text.translate(_LEET)
        if leet != text:
            out.append(("leet", 0, leet))
    for m in _HTML_COMMENT_RE.finditer(text):
        out.append(("html_comment", m.start(1), m.group(1)))
    return out


def normalize(text: str) -> str:
    """NFKC (full-width and look-alike letters fold to ASCII), zero-width characters removed."""
    return _ZW_RE.sub("", unicodedata.normalize("NFKC", text))


def _scan_plain(text: str, layer: str, offset: int) -> list[Finding]:
    found = []
    for family, (weight, rx) in FAMILIES.items():
        for m in rx.finditer(text):
            found.append(Finding(family, weight, offset + m.start(), offset + m.end(), m.group()[:160], layer))
            break  # one hit per family per layer is enough evidence; more would only inflate the score
    return found


def scan(text: str) -> list[Finding]:
    """Every finding in the text and in its hidden layers."""
    if not text:
        return []
    clean = normalize(text)
    findings = _scan_plain(clean, "plain", 0)
    if _BIDI_RE.search(text):
        m = _BIDI_RE.search(text)
        findings.append(Finding("hidden_text", 1.0, m.start(), m.end(), "bidirectional override character", "bidi"))
    if len(_ZW_RE.findall(text)) >= 3 and re.search(r"\w[​‌‍⁠]\w", text):
        findings.append(Finding("hidden_text", 1.0, 0, 0, "zero-width characters inside words", "zero_width"))
    seen = {(f.family, f.layer) for f in findings}
    for layer, offset, decoded in _layers(text):
        if layer == "tags":
            findings.append(Finding("hidden_text", 2.0, offset, offset, "invisible Unicode tag text: " + decoded[:120], "tags"))
        for f in _scan_plain(normalize(decoded), layer, offset):
            if (f.family, f.layer) in seen or (layer == "leet" and (f.family, "plain") in seen):
                continue
            seen.add((f.family, f.layer))
            # A payload someone bothered to hide counts more than the same words in the open.
            bonus = 1.0 if layer in ("tags", "base64", "hex", "spaced", "html_comment") else 0.0
            findings.append(Finding(f.family, f.weight + bonus, f.start, f.end, f.evidence, layer))
    return findings


def score(findings: list[Finding]) -> float:
    """Sum of the heaviest hit per family: several independent signals add up, one repeated signal does not."""
    best: dict[str, float] = {}
    for f in findings:
        best[f.family] = max(best.get(f.family, 0.0), f.weight)
    return round(sum(best.values()), 2)


def verdict(findings: list[Finding]) -> tuple[str, float]:
    """(clean | suspicious | malicious, score)."""
    s = score(findings)
    if s >= MALICIOUS_AT or any(f.layer in CRITICAL_LAYERS and f.family != "hidden_text" for f in findings):
        return "malicious", s
    if s >= SUSPICIOUS_AT:
        return "suspicious", s
    return "clean", s
