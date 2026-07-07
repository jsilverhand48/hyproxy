"""qBittorrent WebUI client for approved portal download requests.

Talks to the instance at settings.qbit_url with no auth cookie: the hyproxy
host is expected to be IP-whitelisted in qBittorrent's WebUI settings
("Bypass authentication for clients in whitelisted IP subnets").
"""

import httpx


class QbitError(Exception):
    """qBittorrent rejected or failed the add-torrent call."""


async def add_torrent(client: httpx.AsyncClient, *, magnet: str, savepath: str) -> None:
    """POST /api/v2/torrents/add. Raises QbitError unless qBittorrent says Ok.

    The WebUI expects multipart/form-data; the (None, value) file tuples force
    httpx to emit multipart without filenames, matching a browser form post.
    qBittorrent answers 200 "Ok." on success and "Fails." / 415 otherwise.
    """
    fields = {
        "urls": magnet,
        "autoTMM": "false",
        "savepath": savepath,
        "rename": "",
        "category": "",
        "stopped": "false",
        "stopCondition": "None",
        "contentLayout": "Original",
        "dlLimit": "0",
        "upLimit": "0",
    }
    try:
        resp = await client.post(
            "/api/v2/torrents/add",
            files={name: (None, value) for name, value in fields.items()},
        )
    except httpx.HTTPError as exc:
        raise QbitError(f"qbittorrent unreachable: {exc.__class__.__name__}") from exc
    if resp.status_code != 200 or resp.text.strip() == "Fails.":
        raise QbitError(f"qbittorrent rejected torrent (status {resp.status_code})")
