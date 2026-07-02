import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


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
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = None


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None

    model_config = {"from_attributes": True}


class ResourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    protocol: Literal["http", "https", "tcp", "vnc", "rdp", "ssh"]
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool = True


class ResourcePatch(BaseModel):
    name: str | None = None
    host: str | None = None
    ports: list[int] | None = None
    path_prefix: str | None = None
    description: str | None = None
    enabled: bool | None = None


class ResourceOut(BaseModel):
    id: uuid.UUID
    name: str
    protocol: str
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
