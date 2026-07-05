import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


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


class ResourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    protocol: Literal["http", "https", "tcp", "vnc", "rdp", "ssh"]
    public_host: str | None = None
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool = True

    _norm_public_host = field_validator("public_host", mode="before")(_normalize_public_host)


class ResourcePatch(BaseModel):
    name: str | None = None
    public_host: str | None = None
    host: str | None = None
    ports: list[int] | None = None
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool | None = None

    _norm_public_host = field_validator("public_host", mode="before")(_normalize_public_host)


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

    model_config = {"from_attributes": True}


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
    protocol: Literal["vnc", "rdp", "ssh"]
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    # Non-secret guacd parameters (all values are strings in the guac protocol).
    params: dict[str, str] = Field(default_factory=dict)
    # Write-only: sealed at rest, never returned. Absent on PUT keeps existing.
    secret_params: dict[str, str] | None = None


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
