"""Glob patterns for the public-resource path allowlist.

A public resource (`Resource.public_access`) is reachable by anyone who has its
password, so what it exposes must be an explicit, auditable allowlist rather
than "the whole hostname". `Resource.public_paths` holds that allowlist as glob
patterns; every request to a public host is matched against them in
authz/check.py and anything unmatched 404s.

Deliberately NOT a regex language. Admin-supplied regexes would run on the
request hot path of an internet-facing host, which is a ReDoS surface, and they
make it far too easy to write a pattern that quietly matches everything. Globs
translate to a fixed, anchored, backtracking-free shape instead:

    /my/uri/path        exact match, nothing else
    /my/uri/path/*      one more segment:  /my/uri/path/example
                        but NOT            /my/uri/path/a/b
    /my/uri/path/**     any depth below:   /my/uri/path/a/b/c
    /assets/*.js        one segment, suffixed: /assets/app.js

This is separate from `Policy.allowed_paths` (policy/engine.py), which is prefix
matching for role-based scoping of *authenticated* users. The two mean different
things and are intentionally not shared.
"""

import re
from functools import lru_cache

# A pattern is admin input, but a public one is internet-reachable, so keep the
# bounds tight and the failure mode "rejected at save time".
MAX_PATTERN_LENGTH = 512
MAX_PATTERNS = 64


class PatternError(ValueError):
    """A public path pattern was rejected at save time."""


def _translate(pattern: str) -> str:
    """Glob -> anchored regex source.

    `**` crosses segment boundaries, `*` does not, everything else is literal.
    No alternation, no quantifiers, no backreferences, so the compiled regex is
    linear in the input and cannot backtrack pathologically.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        char = pattern[i]
        if char == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        out.append(re.escape(char))
        i += 1
    return "\\A" + "".join(out) + "\\Z"


@lru_cache(maxsize=512)
def compile_patterns(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """Compile a resource's pattern tuple once and reuse it per request.

    Keyed on the tuple itself, so editing a resource's patterns produces a new
    key and the stale entry simply ages out; there is nothing to invalidate.
    """
    return tuple(re.compile(_translate(p)) for p in patterns)


def matches(patterns: tuple[str, ...] | list[str] | None, path: str) -> bool:
    """True when `path` is exposed by any of `patterns`. Empty means nothing."""
    if not patterns:
        return False
    for rx in compile_patterns(tuple(patterns)):
        if rx.match(path):
            return True
    return False


def validate_pattern(pattern: str) -> str:
    """Normalize an admin-supplied pattern or raise PatternError.

    Rejects the shapes that would silently defeat the point of the allowlist:
    a bare `/*` or `/**` exposes the entire hostname, and `..` segments let a
    pattern read as narrower than it is.
    """
    p = pattern.strip()
    if not p:
        raise PatternError("pattern is empty")
    if len(p) > MAX_PATTERN_LENGTH:
        raise PatternError(f"pattern is longer than {MAX_PATTERN_LENGTH} characters")
    if "\x00" in p:
        raise PatternError("pattern contains a NUL byte")
    if not p.startswith("/"):
        raise PatternError("pattern must start with '/'")
    if p.startswith("//"):
        raise PatternError("pattern must not start with '//'")
    if "\\" in p:
        raise PatternError("pattern must not contain a backslash")
    if any(seg == ".." for seg in p.split("/")):
        raise PatternError("pattern must not contain a '..' segment")
    if p in ("/*", "/**", "/"):
        raise PatternError(
            "pattern would expose the whole host; list the paths to publish instead"
        )
    return p


def validate_patterns(patterns: list[str]) -> list[str]:
    """Validate a whole allowlist, preserving order and dropping duplicates."""
    if len(patterns) > MAX_PATTERNS:
        raise PatternError(f"at most {MAX_PATTERNS} patterns are allowed")
    seen: set[str] = set()
    out: list[str] = []
    for raw in patterns:
        p = validate_pattern(raw)
        if p not in seen:
            seen.add(p)
            out.append(p)
    if not out:
        raise PatternError("at least one path pattern is required")
    return out


def literal_prefix(pattern: str) -> str:
    """The pattern's fixed leading path, for building a shareable link.

    `/my/uri/path/*` -> `/my/uri/path/`. Used only to show the admin where the
    link points; never for matching.
    """
    head = pattern.split("*", 1)[0]
    return head or "/"
