"""RTSP camera streaming in the browser.

Browsers cannot play RTSP. This package brokers access to a camera and bridges
its stream into a form a stock browser plays with no plugin: ffmpeg remuxes the
RTSP feed to fragmented MP4, which is pushed over an authenticated WebSocket to
a MediaSource-backed <video> element.

Authentication is two-stage. The viewer signs in with the hyproxy IdP and is
policy-checked like any other resource; then they supply the camera's own
username and password, which are prompted per session and NEVER persisted. Those
credentials exist only in browser memory and inside the short-lived, single-use
encrypted stream token.

The shape mirrors `hyproxy.guac`: broker mints a token plus an RtspGrant row,
the data plane single-use-consumes the grant when it forward-auths the
WebSocket, and an internal bridge service decrypts the token and does the work.
"""
