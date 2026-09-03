"""RTSP URL construction, redaction, and codec-string mapping.

Pure functions only: no database, no ffmpeg, no network. The security-relevant
property under test is that a viewer-supplied password can never break out of
the userinfo component and rewrite the host the bridge dials.
"""

from types import SimpleNamespace

import pytest

from hyproxy.rtsp.app import _avc_codec_string, _classify_ffmpeg_error
from hyproxy.rtsp.urls import build_rtsp_url, redact, stream_path


def conn(hostname: str = "10.0.0.9", port: int = 554, **params: str) -> SimpleNamespace:
    return SimpleNamespace(hostname=hostname, port=port, params_json=dict(params))


def test_build_url_uses_db_host_and_path() -> None:
    url = build_rtsp_url(conn(path="/Streaming/Channels/101"), username="ops", password="pw")
    assert url == "rtsp://ops:pw@10.0.0.9:554/Streaming/Channels/101"


def test_password_cannot_rewrite_the_host() -> None:
    # A password containing '@' and '/' must stay inside the userinfo component.
    url = build_rtsp_url(conn(path="/live"), username="ops", password="p@ss/evil.example")
    assert url == "rtsp://ops:p%40ss%2Fevil.example@10.0.0.9:554/live"
    # The authority is still the configured host, not the injected one.
    assert url.rsplit("@", 1)[1].startswith("10.0.0.9:554/")


def test_username_is_also_encoded() -> None:
    url = build_rtsp_url(conn(path="/live"), username="a:b@c", password="x")
    assert url == "rtsp://a%3Ab%40c:x@10.0.0.9:554/live"


def test_no_credentials_means_no_userinfo() -> None:
    assert build_rtsp_url(conn(path="/live"), username="", password="") == (
        "rtsp://10.0.0.9:554/live"
    )


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("/live", "/live"), ("live", "/live"), ("", "/"), (None, "/")],
)
def test_stream_path_normalizes(configured: str | None, expected: str) -> None:
    params = {} if configured is None else {"path": configured}
    assert stream_path(conn(**params)) == expected


def test_redact_strips_credentials() -> None:
    url = "rtsp://ops:hunter2@10.0.0.9:554/live"
    assert redact(url) == "rtsp://***:***@10.0.0.9:554/live"
    assert "hunter2" not in redact(url)


def test_redact_passes_through_url_without_credentials() -> None:
    assert redact("rtsp://10.0.0.9:554/live") == "rtsp://10.0.0.9:554/live"


@pytest.mark.parametrize(
    ("profile", "level", "expected"),
    [
        ("Constrained Baseline", 31, "avc1.42E01F"),
        ("Main", 40, "avc1.4D4028"),
        ("High", 41, "avc1.640029"),
        # Unknown profile or missing level falls back to something playable
        # rather than emitting a codec string the browser will reject outright.
        ("Nonsense", 40, "avc1.4D401F"),
        ("High", None, "avc1.4D401F"),
    ],
)
def test_avc_codec_string(profile: str, level: int | None, expected: str) -> None:
    assert _avc_codec_string(profile, level) == expected


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("rtsp://x: Server returned 401 Unauthorized", "rtsp_auth_failed"),
        ("Server returned 404 Not Found", "rtsp_stream_not_found"),
        ("Connection refused", "rtsp_unreachable"),
        ("something else entirely", "rtsp_failed"),
    ],
)
def test_classify_ffmpeg_error(stderr: str, expected: str) -> None:
    assert _classify_ffmpeg_error(stderr) == expected
