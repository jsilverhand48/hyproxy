"""Path-glob allowlist for public resources (policy/pathglob.py).

The allowlist is the only thing standing between a shared password and the rest
of a backend, so these cover both halves: what a stored pattern matches, and
which patterns are refused at save time.
"""

import pytest

from hyproxy.policy import pathglob


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        # Exact patterns match exactly and nothing below them.
        ("/my/uri/path", "/my/uri/path", True),
        ("/my/uri/path", "/my/uri/path/", False),
        ("/my/uri/path", "/my/uri/path/example", False),
        ("/my/uri/path", "/my/uri", False),
        # A single star spans one segment only.
        ("/my/uri/path/*", "/my/uri/path/example", True),
        ("/my/uri/path/*", "/my/uri/path/", True),
        ("/my/uri/path/*", "/my/uri/path/a/b", False),
        ("/my/uri/path/*", "/my/uri/path", False),
        # A double star spans any depth.
        ("/my/uri/path/**", "/my/uri/path/a/b/c", True),
        ("/my/uri/path/**", "/my/uri/path/example", True),
        ("/my/uri/path/**", "/other", False),
        # Stars compose with literal suffixes.
        ("/assets/*.js", "/assets/app.js", True),
        ("/assets/*.js", "/assets/app.css", False),
        ("/assets/*.js", "/assets/vendor/app.js", False),
        # Regex metacharacters in a pattern are literal, not operators.
        ("/a.b/c", "/axb/c", False),
        ("/a+b", "/aab", False),
    ],
)
def test_matches(pattern: str, path: str, expected: bool) -> None:
    assert pathglob.matches([pattern], path) is expected


def test_matches_any_of_several_patterns() -> None:
    patterns = ["/docs/**", "/assets/*.js", "/health"]
    assert pathglob.matches(patterns, "/docs/a/b")
    assert pathglob.matches(patterns, "/assets/app.js")
    assert pathglob.matches(patterns, "/health")
    assert not pathglob.matches(patterns, "/admin")


def test_empty_allowlist_matches_nothing() -> None:
    """Fail closed: a public resource with no patterns exposes no path."""
    assert not pathglob.matches(None, "/")
    assert not pathglob.matches([], "/anything")


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "   ",
        "relative/path",
        "//evil.example.com/x",
        "/a/../b",
        "/a\\b",
        "/x\x00y",
        "/" + "a" * (pathglob.MAX_PATTERN_LENGTH + 1),
    ],
)
def test_validate_pattern_rejects(pattern: str) -> None:
    with pytest.raises(pathglob.PatternError):
        pathglob.validate_pattern(pattern)


@pytest.mark.parametrize("pattern", ["/", "/*", "/**"])
def test_validate_pattern_rejects_whole_host(pattern: str) -> None:
    """The point of the allowlist is that it is narrower than the hostname."""
    with pytest.raises(pathglob.PatternError):
        pathglob.validate_pattern(pattern)


def test_validate_patterns_trims_and_dedupes_preserving_order() -> None:
    assert pathglob.validate_patterns(["  /b/*  ", "/a", "/b/*"]) == ["/b/*", "/a"]


def test_validate_patterns_requires_at_least_one() -> None:
    with pytest.raises(pathglob.PatternError):
        pathglob.validate_patterns([])


def test_validate_patterns_caps_count() -> None:
    with pytest.raises(pathglob.PatternError):
        pathglob.validate_patterns([f"/p{i}" for i in range(pathglob.MAX_PATTERNS + 1)])


def test_literal_prefix() -> None:
    assert pathglob.literal_prefix("/my/uri/path/*") == "/my/uri/path/"
    assert pathglob.literal_prefix("/my/uri/path") == "/my/uri/path"
    assert pathglob.literal_prefix("*") == "/"
