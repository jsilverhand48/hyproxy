from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The server/ directory (src/hyproxy/config.py -> parents[2]); anchor for relative paths
# so .env stays portable regardless of the working directory.
SERVER_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HYPROXY_", env_file=SERVER_DIR / ".env", extra="ignore"
    )

    db_url: str = "postgresql+asyncpg://hyproxy:devonly@127.0.0.1:5433/hyproxy"
    # Async engine pool, per process (each app process holds its own pool).
    db_pool_size: int = 10
    db_max_overflow: int = 10
    master_key_file: str = "./.dev/master.keys"
    # Secrets backend: "file" (dev, key on disk) or "tpm" (production, master key
    # sealed to the TPM and unsealed into memory only). See core/secrets.py.
    secrets_backend: str = "file"
    # Path to the TPM-sealed master-key blob (used only when secrets_backend=tpm;
    # unsealed via tpm2-tools at startup). See docs/production.md.
    tpm_sealed_blob: str = ""
    # PCR selection the blob was sealed under. MUST match sealing time exactly
    # (tpm2_unseal re-satisfies the policy with it); see docs/TPM_STEPS.md.
    tpm_pcrs: str = "sha256:0,2,4,7"

    @field_validator("db_url")
    @classmethod
    def _absolutize_socket_host(cls, v: str) -> str:
        # asyncpg treats host= as a unix socket dir only when absolute.
        marker = "host="
        if marker in v:
            prefix, _, hostval = v.partition(marker)
            if hostval and not hostval.startswith("/") and "://" not in hostval:
                v = prefix + marker + str((SERVER_DIR / hostval).resolve())
        return v

    @field_validator("master_key_file")
    @classmethod
    def _absolutize_key_file(cls, v: str) -> str:
        p = Path(v)
        return str(p if p.is_absolute() else (SERVER_DIR / p).resolve())

    issuer: str = "https://idp.localhost:8300"

    # TTLs (seconds)
    access_ttl: int = 600
    refresh_abs_ttl: int = 21600
    idle_ttl: int = 1800
    stepup_max_age: int = 300
    dpop_iat_window: int = 300
    dpop_iat_future_skew: int = 30
    auth_code_ttl: int = 60
    login_flow_ttl: int = 600

    # Session touch write throttle (seconds)
    session_touch_interval: int = 60

    # Data-plane authz decision cache TTL (seconds). Sent only with allow
    # decisions whose granting policy is path/time-independent; bounds
    # revocation latency for those hosts. 0 disables caching hints.
    authz_cache_ttl: int = 20

    # JWKS
    jwks_cache_max_age: int = 300
    signing_alg: str = "ES256"

    # Gateway (the data plane's OIDC relying party, served via the authz app)
    gateway_client_id: str = "gateway"
    auth_host: str = "auth.localhost"
    external_scheme: str = "https"
    gateway_cookie_name: str = "__Secure-gw"
    gateway_cookie_domain: str = ""  # empty = host-only; prod: parent domain
    gateway_state_ttl: int = 600
    # Backchannel from the authz service to the IdP token endpoint. Defaults to
    # the issuer; override when the internal address differs. verify=False only
    # for dev self-signed certs.
    idp_internal_url: str = ""
    idp_verify_tls: bool = True
    # Trust the data plane's X-Forwarded-For for the real client IP. Enable when
    # the control plane sits behind the data plane (the sole TLS ingress, which
    # sanitizes the header); leave off for direct-TLS/dev. Must be consistent
    # everywhere or session source-IP binding force-loops re-auth.
    trust_forwarded_for: bool = False

    # Admin UI (React SPA). Its origin (scheme://host[:port]) is the sole CORS
    # allowance on the IdP token/userinfo endpoints and the only permitted
    # step-up return target. Empty disables both (default: no admin UI wired).
    admin_ui_origin: str = ""
    # Built SPA to serve from the admin app. Empty resolves to ../ui/dist; the
    # admin app serves it only when the directory exists (so an unbuilt tree
    # still runs the API alone).
    admin_ui_dist: str = ""
    # Comma-separated client networks allowed to use the admin API (e.g.
    # "10.0.0.0/24,127.0.0.0/8"). Defense in depth behind the data plane's
    # lan_only edge block: the containerized admin app cannot see the host's
    # interfaces, so the LAN must be spelled out. Empty disables the check
    # (dev default).
    admin_lan_cidrs: str = ""

    # Standard-user portal. The SPA is also served on this second, internet
    # facing origin (scheme://host[:port]); it selects the DPoP htu for portal
    # requests, is CORS-allowed on the IdP alongside admin_ui_origin, and is a
    # valid step-up return target. Empty disables the portal origin (default).
    portal_origin: str = ""

    # qBittorrent WebUI used for approved peer-to-peer download requests. The
    # hyproxy host must be IP-whitelisted in qBittorrent (no auth cookie is
    # sent). The savepaths back the portal's Shows/Movies destination choices;
    # an empty savepath disables submissions for that target.
    qbit_url: str = "http://10.10.1.4:8080"
    qbit_savepath_shows: str = ""
    qbit_savepath_movies: str = ""

    # Guacamole browser bridges (Phase 4). guac_cypher_key is base64 of the
    # 32-byte AES-256-CBC key shared with the Node guacamole-lite tunnel; the
    # broker mints tokens under it. Empty disables guac. guac_grant_ttl bounds
    # how long a minted tunnel token is valid.
    guac_cypher_key: str = ""
    guac_grant_ttl: int = 60

    # Centralized logging (see logs.py). log_dir empty = stderr only (dev);
    # production sets /var/log/hyproxy. Rotation keeps log_backup_count
    # archives (x.log.1, x.log.2) and deletes older ones.
    log_dir: str = ""
    log_level: str = "INFO"
    log_max_bytes: int = 52428800  # 50 MB
    log_backup_count: int = 2

    # Rate limiting
    throttle_window: int = 900
    throttle_account_free_failures: int = 3
    throttle_account_max_delay: int = 60
    throttle_ip_free_failures: int = 10
    throttle_ip_max_delay: int = 30


@lru_cache
def get_settings() -> Settings:
    return Settings()
