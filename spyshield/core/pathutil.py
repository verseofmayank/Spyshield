"""Cross-platform path normalisation and glob matching used by rules and allowlists."""
from __future__ import annotations

import fnmatch
import os
import re


def norm(path: str | None) -> str:
    """Lowercase, forward slashes, no trailing slash, env-var style placeholders untouched."""
    if not path:
        return ""
    p = path.strip().strip('"').replace("\\", "/").lower()
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p


def matches_any(path: str | None, patterns: list[str]) -> str | None:
    """Return the first glob pattern matching the (normalised) path, else None."""
    p = norm(path)
    if not p:
        return None
    for pat in patterns:
        if fnmatch.fnmatchcase(p, norm(pat)):
            return pat
    return None


def basename(path: str | None) -> str:
    return norm(path).rsplit("/", 1)[-1]


def extension(path: str | None) -> str:
    return os.path.splitext(basename(path))[1]


_EXE_RE = re.compile(r'^\s*(?:"([^"]+)"|([^\s]+(?:\s[^\s/-][^\s]*)*?\.(?:exe|bat|cmd|com|scr|ps1|vbs|js|jse|wsf|msi|dll|lnk|cpl)))', re.I)


def extract_target_path(command: str | None) -> str | None:
    """Best-effort: the executable/script referenced by a Run-key value or startup command.

    Handles quoted paths and unquoted paths with a known extension; returns None when unsure.
    """
    if not command:
        return None
    cmd = os.path.expandvars(command.strip()) if "%" in command and os.name == "nt" else command.strip()
    m = _EXE_RE.match(cmd)
    if m:
        return (m.group(1) or m.group(2)).strip()
    first = cmd.split()[0] if cmd.split() else None
    return first.strip('"') if first else None
