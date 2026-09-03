"""guacamole-lite token codec.

The codec itself is generic and lives in `hyproxy.core.sealedtoken`; the RTSP
bridge uses the same envelope under a different key. This module keeps the
guac-facing names so the broker and the tests read as guac code, and documents
the one thing that is guac-specific: the envelope shape here MUST stay
byte-compatible with guacamole-lite's default `Crypt` (AES-256-CBC), because
the Node tunnel decrypts these tokens with the shared HYPROXY_GUAC_CYPHER_KEY.
"""

from hyproxy.core.sealedtoken import decrypt_token, load_cypher_key, mint_token

__all__ = ["decrypt_token", "load_cypher_key", "mint_token"]
