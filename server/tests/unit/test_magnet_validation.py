"""The portal magnet validator must only pass BitTorrent v1 magnet URIs.

qBittorrent's `urls` field also accepts http(s) URLs and local file paths, so
anything the regex lets through gets fetched by the server on approval.
"""

import pytest

from hyproxy.admin.schemas import MAGNET_RE, DownloadRequestIn

HEX40 = "a" * 40
BASE32 = "A2B3C4D5E6F7G2H3I4J5K6L7M2N3O4P5"  # 32 chars of [A-Z2-7]


@pytest.mark.parametrize(
    "value",
    [
        f"magnet:?xt=urn:btih:{HEX40}",
        f"magnet:?xt=urn:btih:{HEX40.upper()}",
        f"magnet:?xt=urn:btih:{BASE32}",
        f"magnet:?xt=urn:btih:{HEX40}&dn=name&tr=udp%3A%2F%2Ftracker%3A80",
    ],
)
def test_valid_magnets_pass(value: str) -> None:
    assert MAGNET_RE.match(value)
    assert DownloadRequestIn(magnet=value, target="alpha").magnet == value


@pytest.mark.parametrize(
    "value",
    [
        "http://10.10.1.4:8080/steal",
        "https://example.com/file.torrent",
        "/etc/passwd",
        "file:///etc/passwd",
        f"magnet:?xt=urn:btmh:{HEX40}",  # v2 multihash deliberately excluded
        "magnet:?xt=urn:btih:tooshort",
        f"magnet:?xt=urn:btih:{HEX40}zz",  # overlong hash
        f" magnet:?xt=urn:btih:{HEX40}\nhttp://evil",  # smuggled second line
        f"magnet:?xt=urn:btih:{HEX40} http://evil",  # space-smuggled URL
        "",
    ],
)
def test_invalid_inputs_rejected(value: str) -> None:
    assert not MAGNET_RE.match(value.strip() if value.strip() else value)
    with pytest.raises(ValueError):
        DownloadRequestIn(magnet=value, target="alpha")


def test_target_restricted_to_alpha_bravo() -> None:
    with pytest.raises(ValueError):
        DownloadRequestIn(magnet=f"magnet:?xt=urn:btih:{HEX40}", target="charlie")  # type: ignore[arg-type]
