import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

UUID_PK = UUID(as_uuid=True)
TZ = DateTime(timezone=True)
NOW = text("now()")
GEN_UUID = text("gen_random_uuid()")


class Base(DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012 (SQLAlchemy declarative configuration)
        dict[str, Any]: JSONB,
        datetime: TZ,
        uuid.UUID: UUID_PK,
    }


# --- Core control-plane tables (spec section 5) -----------------------------


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("status IN ('active','disabled')", name="users_status_check"),
        CheckConstraint("auth_tier IN ('standard','admin')", name="users_auth_tier_check"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    external_id: Mapped[str] = mapped_column(Text, unique=True)  # stable OIDC sub
    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    display_name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'active'"))
    # First-class attribute deciding the second factor at login time; never derived from roles.
    auth_tier: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(server_default=NOW)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    name: Mapped[str] = mapped_column(Text, unique=True)
    description: Mapped[str | None] = mapped_column(Text)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (
        CheckConstraint(
            "protocol IN ('http','https','tcp','vnc','rdp','ssh')",
            name="resources_protocol_check",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    name: Mapped[str] = mapped_column(Text, unique=True)
    protocol: Mapped[str] = mapped_column(Text)
    # Public hostname the data plane serves this resource on (routing key).
    public_host: Mapped[str | None] = mapped_column(CITEXT, unique=True)
    host: Mapped[str] = mapped_column(Text)
    ports: Mapped[list[int]] = mapped_column(ARRAY(Integer))
    path_prefix: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class ResourceConnection(Base):
    """Guacamole connection parameters for a non-HTTP resource (Phase 4).

    One row per resource. Secret parameters (passwords, private keys) are sealed
    with AES-256-GCM under the master key exactly like TOTP secrets; only the
    parameter names live in cleartext (`secret_keys`) so the admin UI can show
    which secrets are set without ever decrypting them."""

    __tablename__ = "resource_connections"
    __table_args__ = (
        CheckConstraint(
            "protocol IN ('vnc','rdp','ssh')", name="resource_connections_protocol_check"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    resource_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("resources.id", ondelete="CASCADE"), unique=True
    )
    protocol: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str] = mapped_column(Text)
    port: Mapped[int] = mapped_column(Integer)
    # Non-secret guacd parameters (e.g. {"ignore-cert": "true", "username": "x"}).
    params_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    # Sealed JSON of secret parameters (password, private-key, passphrase, ...).
    secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_id: Mapped[str | None] = mapped_column(Text)
    secret_keys: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(server_default=NOW)


class GuacGrant(Base):
    """Single-use, short-lived authorization to open a Guacamole tunnel for a
    resolved connection. Minted by the broker after a policy allow; consumed by
    the data plane on WebSocket connect (where liveness is re-checked). The
    token itself is opaque to us; we store only its hash."""

    __tablename__ = "guac_grants"
    __table_args__ = (Index("ix_guac_grants_expires_at", "expires_at"),)

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    resource_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"))
    connection_id: Mapped[uuid.UUID]
    source_ip: Mapped[str] = mapped_column(INET)
    issued_at: Mapped[datetime] = mapped_column(server_default=NOW)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint("action IN ('allow','deny')", name="policies_action_check"),
        Index("ix_policies_role_id", "role_id"),
        Index("ix_policies_resource_id", "resource_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"))
    resource_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"))
    allowed_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer))
    allowed_paths: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    action: Mapped[str] = mapped_column(Text)
    conditions_json: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint("auth_tier IN ('standard','admin')", name="sessions_auth_tier_check"),
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_absolute_expires_at", "absolute_expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    cookie_secret_hash: Mapped[str] = mapped_column(Text)  # sha256 of the cookie secret
    source_ip: Mapped[str] = mapped_column(INET)
    auth_tier: Mapped[str] = mapped_column(Text)  # frozen at login time
    amr: Mapped[list[str]] = mapped_column(ARRAY(Text))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    dpop_jkt: Mapped[str | None] = mapped_column(Text)  # set at first token issuance
    issued_at: Mapped[datetime] = mapped_column(server_default=NOW)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=NOW)
    absolute_expires_at: Mapped[datetime]
    step_up_verified_at: Mapped[datetime | None]
    stepup_challenge: Mapped[bytes | None] = mapped_column(LargeBinary)
    stale: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    revoked_at: Mapped[datetime | None]
    revoke_reason: Mapped[str | None] = mapped_column(Text)


class PolicyChange(Base):
    __tablename__ = "policy_changes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(server_default=NOW)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    entity_type: Mapped[str] = mapped_column(Text)
    entity_id: Mapped[uuid.UUID | None]
    action: Mapped[str] = mapped_column(Text)
    change_json: Mapped[dict[str, Any]]


class AuditLog(Base):
    """Data-plane access decisions; created now, populated by the Go plane in Phase 2."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_ts", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(server_default=NOW)
    user_id: Mapped[uuid.UUID | None]
    resource_id: Mapped[uuid.UUID | None]
    port: Mapped[int | None] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(INET)


class LogShipCursor(Base):
    """Per-stream high-water mark for off-box log shipping (Phase 5). Append-only
    export: each stream advances its last shipped BigInteger id."""

    __tablename__ = "log_ship_cursors"

    stream: Mapped[str] = mapped_column(Text, primary_key=True)
    last_id: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    updated_at: Mapped[datetime] = mapped_column(server_default=NOW)


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (
        Index("ix_auth_events_ts", "ts"),
        Index("ix_auth_events_user_id_ts", "user_id", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(server_default=NOW)
    event_type: Mapped[str] = mapped_column(Text)
    user_id: Mapped[uuid.UUID | None]
    session_id: Mapped[uuid.UUID | None]
    client_id: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(INET)
    success: Mapped[bool] = mapped_column(Boolean)
    detail: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))


# --- IdP tables --------------------------------------------------------------


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    client_id: Mapped[str] = mapped_column(Text, unique=True)
    client_name: Mapped[str] = mapped_column(Text)
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(Text))  # exact-match set
    token_endpoint_auth_method: Mapped[str] = mapped_column(Text, server_default=text("'none'"))
    require_dpop: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    allowed_scopes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("ARRAY['openid','profile','email']")
    )
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)


class AuthCode(Base):
    __tablename__ = "auth_codes"
    __table_args__ = (
        CheckConstraint("code_challenge_method = 'S256'", name="auth_codes_pkce_method_check"),
    )

    code_hash: Mapped[str] = mapped_column(Text, primary_key=True)  # sha256(code)
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    redirect_uri: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(Text)
    code_challenge_method: Mapped[str] = mapped_column(Text, server_default=text("'S256'"))
    auth_time: Mapped[datetime]
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_session_id", "session_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)  # sha256(token)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    family_id: Mapped[uuid.UUID]
    parent_id: Mapped[uuid.UUID | None]
    client_id: Mapped[str] = mapped_column(Text)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    dpop_jkt: Mapped[str] = mapped_column(Text)  # cnf binding
    scope: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(server_default=NOW)
    expires_at: Mapped[datetime]  # capped at session absolute expiry
    used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class DpopJtiSeen(Base):
    __tablename__ = "dpop_jti_seen"
    __table_args__ = (
        PrimaryKeyConstraint("jkt", "jti", name="dpop_jti_seen_pkey"),
        Index("ix_dpop_jti_seen_expires_at", "expires_at"),
    )

    jkt: Mapped[str] = mapped_column(Text)
    jti: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime]


class SigningKey(Base):
    __tablename__ = "signing_keys"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending','active','retiring','retired')",
            name="signing_keys_state_check",
        ),
        # Exactly one active key at any time.
        Index(
            "ux_signing_keys_single_active",
            "state",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    kid: Mapped[str] = mapped_column(Text, unique=True)
    alg: Mapped[str] = mapped_column(Text, server_default=text("'ES256'"))
    state: Mapped[str] = mapped_column(Text)
    public_jwk: Mapped[dict[str, Any]]
    private_key_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(Text)  # master key that encrypted the private key
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    activated_at: Mapped[datetime | None]
    retiring_at: Mapped[datetime | None]
    retired_at: Mapped[datetime | None]


class UserTotp(Base):
    __tablename__ = "user_totp"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    confirmed_at: Mapped[datetime | None]  # null until enrollment verified


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"
    __table_args__ = (Index("ix_webauthn_credentials_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)  # COSE
    sign_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    transports: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    aaguid: Mapped[uuid.UUID | None]
    friendly_name: Mapped[str] = mapped_column(Text)
    break_glass: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    last_used_at: Mapped[datetime | None]


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    __table_args__ = (
        Index(
            "ix_recovery_codes_user_id_unused",
            "user_id",
            postgresql_where=text("used_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    batch_id: Mapped[uuid.UUID]
    code_hash: Mapped[str] = mapped_column(Text)  # argon2id
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)


class LoginFlow(Base):
    __tablename__ = "login_flows"
    __table_args__ = (
        CheckConstraint(
            "stage IN ('password','totp','webauthn','done')", name="login_flows_stage_check"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    csrf_token_hash: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(INET)
    stage: Mapped[str] = mapped_column(Text, server_default=text("'password'"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )  # set after password step
    webauthn_challenge: Mapped[bytes | None] = mapped_column(LargeBinary)
    recovery_used: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    oidc_request: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    expires_at: Mapped[datetime]


class GatewaySession(Base):
    """Browser session at the auth gateway (the data plane's RP), linked to
    the IdP session so liveness/revocation are inherited on every check."""

    __tablename__ = "gateway_sessions"
    __table_args__ = (Index("ix_gateway_sessions_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=GEN_UUID)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    idp_session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    cookie_secret_hash: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(INET)
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    revoked_at: Mapped[datetime | None]


class GatewayLoginState(Base):
    """Single-use state for an in-flight gateway OIDC login (10 min TTL)."""

    __tablename__ = "gateway_login_states"

    state_hash: Mapped[str] = mapped_column(Text, primary_key=True)  # sha256(state)
    code_verifier: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(Text)
    return_url: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(INET)
    created_at: Mapped[datetime] = mapped_column(server_default=NOW)
    expires_at: Mapped[datetime]


class AuthThrottle(Base):
    __tablename__ = "auth_throttle"
    __table_args__ = (
        PrimaryKeyConstraint("scope", "key", name="auth_throttle_pkey"),
        CheckConstraint("scope IN ('ip','account')", name="auth_throttle_scope_check"),
    )

    scope: Mapped[str] = mapped_column(Text)
    key: Mapped[str] = mapped_column(Text)
    failure_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    window_started_at: Mapped[datetime] = mapped_column(server_default=NOW)
    next_allowed_at: Mapped[datetime] = mapped_column(server_default=NOW)
