"""Phase 4: Guacamole browser bridges (RDP/VNC/SSH).

The broker mints short-lived, single-use guacamole-lite tokens carrying the
resolved connection (secrets unsealed at mint time only); the Node tunnel
service decrypts them and connects to guacd. Nothing in this package ever hands
raw connection credentials to the browser.
"""
