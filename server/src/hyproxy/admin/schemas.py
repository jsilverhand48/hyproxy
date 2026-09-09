import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from hyproxy.policy import pathglob


class Page[T](BaseModel):
    """Keyset-paginated envelope. `next_cursor` is the id to pass as `cursor`
    for the following page, or null when the last page has been returned."""

    items: list[T]
    next_cursor: int | None = None


class UserCreate(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=128)
    auth_tier: Literal["standard", "admin"]
    temp_password: str = Field(min_length=12, max_length=128)


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    status: Literal["active", "disabled"] | None = None
    auth_tier: Literal["standard", "admin"] | None = None


class UserOut(BaseModel):
    id: uuid.UUID
    external_id: str
    email: str
    display_name: str
    status: str
    auth_tier: str
    is_protected: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class PasswordResetIn(BaseModel):
    temp_password: str = Field(min_length=12, max_length=128)


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = None


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None

    model_config = {"from_attributes": True}


def _normalize_public_host(v: object) -> object:
    """Normalize and validate a resource's public routing host.

    Mirrors the data plane's `routing.NormalizeHost` (lowercase, <=253 chars,
    DNS labels of a-z/0-9/-, no leading/trailing hyphen): the data plane rejects
    anything else at the edge, so refuse it here rather than store a host that
    can never route. Returns None unchanged (a resource with no routing host is
    valid; it simply has no route)."""
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("public_host must be a string")
    host = v.strip().lower().rstrip(".")
    if not host or len(host) > 253:
        raise ValueError("public_host must be 1-253 characters")
    for label in host.split("."):
        if not label or len(label) > 63:
            raise ValueError("public_host has an empty or over-long label")
        if label[0] == "-" or label[-1] == "-":
            raise ValueError("public_host label may not start or end with '-'")
        if not all(c == "-" or c.isdigit() or ("a" <= c <= "z") for c in label):
            raise ValueError("public_host may only contain a-z, 0-9, and '-'")
    return host


class ResourceConnectionIn(BaseModel):
    """Backend connection details nested in ResourceCreate (protocol comes from
    the resource itself)."""

    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    # Non-secret guacd parameters (all values are strings in the guac protocol).
    params: dict[str, str] = Field(default_factory=dict)
    # Write-only: sealed at rest, never returned.
    secret_params: dict[str, str] | None = None


GUAC_PROTOCOLS = {"vnc", "rdp", "ssh"}
# Protocols reached through a fixed path on the portal host instead of their own
# public hostname, so they never appear in the data plane's route table.
TUNNEL_PROTOCOLS = GUAC_PROTOCOLS | {"rtsp"}


def _normalize_public_paths(v: Any) -> Any:
    """Validate the public path allowlist at save time.

    pathglob rejects the shapes that would defeat the allowlist (a bare /* or
    /**, '..' segments, relative patterns), so a stored pattern is always safe
    to compile and match on the request path.
    """
    if v is None:
        return None
    if not isinstance(v, list):
        raise ValueError("public_paths must be a list of path patterns")
    try:
        return pathglob.validate_patterns([str(p) for p in v])
    except pathglob.PatternError as exc:
        raise ValueError(str(exc)) from exc


def _check_public_shape(
    *, public_access: bool, protocol: str | None, public_host: str | None,
    public_paths: list[str] | None,
) -> None:
    """Public mode is only coherent for an L7 resource with a host and paths.

    Mirrors the resources_public_access_shape_check DB constraint so the API
    returns a 422 explaining the problem instead of a raw integrity error.
    """
    if not public_access:
        return
    if protocol is not None and protocol not in {"http", "https"}:
        raise ValueError("public access is only available for http/https resources")
    if not public_host:
        raise ValueError("a public resource needs a public_host to be reached on")
    if not public_paths:
        raise ValueError("a public resource needs at least one public path pattern")


class ResourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    protocol: Literal["http", "https", "tcp", "vnc", "rdp", "ssh", "rtsp"]
    public_host: str | None = None
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool = True
    # Password-only public access. The password itself is never an input: it is
    # generated server-side and returned once (see ResourceCreateOut).
    public_access: bool = False
    public_paths: list[str] | None = None
    # Required for vnc/rdp/ssh/rtsp, forbidden otherwise.
    connection: ResourceConnectionIn | None = None

    _norm_public_host = field_validator("public_host", mode="before")(_normalize_public_host)
    _norm_public_paths = field_validator("public_paths", mode="before")(_normalize_public_paths)

    @model_validator(mode="after")
    def _check_protocol_shape(self) -> "ResourceCreate":
        if self.protocol in TUNNEL_PROTOCOLS:
            if self.public_host is not None:
                raise ValueError(
                    "tunnelled resources are reached via the portal and cannot have a public_host"
                )
            if self.connection is None:
                raise ValueError("vnc/rdp/ssh/rtsp resources require connection details")
            # RTSP credentials are supplied by the viewer per session, so there
            # is nothing to seal and nothing that should ever be stored.
            if self.protocol == "rtsp" and self.connection.secret_params:
                raise ValueError("rtsp credentials are supplied per session and are not stored")
        elif self.connection is not None:
            raise ValueError("connection is only valid for vnc/rdp/ssh/rtsp resources")
        _check_public_shape(
            public_access=self.public_access,
            protocol=self.protocol,
            public_host=self.public_host,
            public_paths=self.public_paths,
        )
        return self


class ResourcePatch(BaseModel):
    name: str | None = None
    public_host: str | None = None
    host: str | None = None
    ports: list[int] | None = None
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool | None = None
    public_access: bool | None = None
    public_paths: list[str] | None = None

    _norm_public_host = field_validator("public_host", mode="before")(_normalize_public_host)
    _norm_public_paths = field_validator("public_paths", mode="before")(_normalize_public_paths)

    # Cross-field coherence needs the stored row too (a PATCH may set only one
    # of the three), so the full check lives in the route handler; see
    # _validate_public_shape in admin/routes/resources.py.


class ResourceOut(BaseModel):
    id: uuid.UUID
    name: str
    protocol: str
    public_host: str | None
    host: str
    ports: list[int]
    path_prefix: str | None
    description: str | None
    enabled: bool
    public_access: bool
    public_paths: list[str] | None
    # Whether a share password has been generated. Read off the stored hash via
    # an alias so the hash itself is never a field on this model and cannot be
    # serialized by accident; the password is shown exactly once, at generation.
    public_password_set: bool = Field(
        default=False, validation_alias="public_password_hash"
    )

    model_config = {"from_attributes": True, "populate_by_name": True}

    @field_validator("public_password_set", mode="before")
    @classmethod
    def _derive_password_set(cls, v: Any) -> bool:
        return bool(v)


class ResourceCreateOut(ResourceOut):
    """Create response. Carries the generated share password ONCE, when the
    resource was created public; it can never be read back afterwards."""

    public_password: str | None = None


class PublicPasswordOut(BaseModel):
    """Rotation response: the new share password, shown once."""

    password: str


class PolicyCreate(BaseModel):
    role_id: uuid.UUID
    resource_id: uuid.UUID
    action: Literal["allow", "deny"]
    allowed_ports: list[int] | None = None
    allowed_paths: list[str] | None = None
    conditions_json: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class PolicyPatch(BaseModel):
    action: Literal["allow", "deny"] | None = None
    allowed_ports: list[int] | None = None
    allowed_paths: list[str] | None = None
    conditions_json: dict[str, Any] | None = None
    enabled: bool | None = None


class PolicyOut(BaseModel):
    id: uuid.UUID
    role_id: uuid.UUID
    resource_id: uuid.UUID
    action: str
    allowed_ports: list[int] | None
    allowed_paths: list[str] | None
    conditions_json: dict[str, Any]
    enabled: bool

    model_config = {"from_attributes": True}


class ResourceConnectionUpsert(BaseModel):
    protocol: Literal["vnc", "rdp", "ssh", "rtsp"]
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    # Non-secret backend parameters (guacd params, or "path"/"audio" for rtsp).
    params: dict[str, str] = Field(default_factory=dict)
    # Write-only: sealed at rest, never returned. Absent on PUT keeps existing.
    secret_params: dict[str, str] | None = None

    @model_validator(mode="after")
    def _check_secrets(self) -> "ResourceConnectionUpsert":
        if self.protocol == "rtsp" and self.secret_params:
            raise ValueError("rtsp credentials are supplied per session and are not stored")
        return self


class ResourceConnectionOut(BaseModel):
    id: uuid.UUID
    resource_id: uuid.UUID
    protocol: str
    hostname: str
    port: int
    params: dict[str, str]
    secret_keys: list[str]  # names only; values never leave the server
    has_secret: bool


class CredentialOut(BaseModel):
    id: uuid.UUID
    friendly_name: str
    break_glass: bool
    created_at: datetime
    last_used_at: datetime | None

    model_config = {"from_attributes": True}


class SessionOut(BaseModel):
    id: uuid.UUID
    source_ip: str
    auth_tier: str
    issued_at: datetime
    last_seen_at: datetime
    stale: bool
    revoked_at: datetime | None

    model_config = {"from_attributes": True}


# --- Viewers (read-only audit / change history) ------------------------------


def _ip_to_str(v: object) -> object:
    # The INET column deserializes to ipaddress.IPv4Address/IPv6Address.
    return str(v) if v is not None else v


class AuditAccessOut(BaseModel):
    id: int
    ts: datetime
    user_id: uuid.UUID | None
    resource_id: uuid.UUID | None
    port: int | None
    decision: str
    reason: str | None
    source_ip: str

    model_config = {"from_attributes": True}

    _norm_ip = field_validator("source_ip", mode="before")(_ip_to_str)


class AuthEventOut(BaseModel):
    id: int
    ts: datetime
    event_type: str
    user_id: uuid.UUID | None
    session_id: uuid.UUID | None
    client_id: str | None
    source_ip: str
    success: bool
    detail: dict[str, Any]

    model_config = {"from_attributes": True}

    _norm_ip = field_validator("source_ip", mode="before")(_ip_to_str)


class PolicyChangeOut(BaseModel):
    id: int
    ts: datetime
    actor_id: uuid.UUID
    actor_email: str | None
    entity_type: str
    entity_id: uuid.UUID | None
    action: str
    change_json: dict[str, Any]


# Standard-user portal ---------------------------------------------------------

# Strictly a BitTorrent v1 magnet URI: 40-hex or 32-base32 infohash, optionally
# followed by additional &-separated params. qBittorrent's `urls` field also
# accepts http(s) URLs and local paths, so anything looser would let a portal
# user make the server fetch arbitrary URLs on approval.
MAGNET_RE = re.compile(
    r"^magnet:\?xt=urn:btih:(?:[0-9a-fA-F]{40}|[a-zA-Z2-7]{32})(?:&\S*)?$"
)


class MyResourceOut(BaseModel):
    """Resource listing for the caller. Deliberately omits internal host/ports."""

    id: uuid.UUID
    name: str
    protocol: str
    public_host: str | None
    description: str | None

    model_config = {"from_attributes": True}


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class DownloadRequestIn(BaseModel):
    magnet: str = Field(max_length=2048)
    target: Literal["shows", "movies"]

    @field_validator("magnet")
    @classmethod
    def _magnet_uri_only(cls, v: str) -> str:
        v = v.strip()
        if not MAGNET_RE.match(v):
            raise ValueError("must be a magnet:?xt=urn:btih: URI")
        return v


class DownloadRequestOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    user_email: str | None = None
    magnet: str
    target: str
    status: str
    created_at: datetime
    reviewed_by: uuid.UUID | None
    reviewed_at: datetime | None
    submitted_at: datetime | None
    error: str | None

    model_config = {"from_attributes": True}
