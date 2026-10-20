"""Redaction of secrets in command lines and free text before anything is stored or reported."""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_SECRET_WORDS = r"(?:password|passwd|pwd|pass|secret|token|apikey|api[-_]key|access[-_]key|auth|authorization|bearer|credential|client[-_]secret|private[-_]key|session|sig(?:nature)?)"

_PATTERNS = [
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # key=value, key:value, --key=value, /key:value (value up to whitespace or quote)
    (re.compile(rf"(?i)((?:--?|/)?[\w.-]*{_SECRET_WORDS}[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s\"']+)"), r"\1" + REDACTED),
    # --password value / -p-style long options with separate value
    (re.compile(rf"(?i)((?:--|/)[\w-]*{_SECRET_WORDS}[\w-]*\s+)(\"[^\"]*\"|'[^']*'|[^\s\"'-][^\s\"']*)"), r"\1" + REDACTED),
    # URL userinfo  scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
    # well-known token shapes
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), REDACTED),
]


def redact(text: str | None, max_len: int = 1000) -> str | None:
    """Redact secrets and bound the length (long command lines are truncated, not stored whole)."""
    if text is None:
        return None
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    if len(out) > max_len:
        out = out[:max_len] + "...[truncated]"
    return out
