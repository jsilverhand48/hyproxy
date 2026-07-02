"""Off-box shipping: severity classification and record projection."""

from datetime import UTC, datetime

from hyproxy.audit.events import AuthEventType
from hyproxy.audit.shipping import _fmt_audit_log, _fmt_auth_event, is_high_severity
from hyproxy.db.models import AuditLog, AuthEvent


def test_high_severity_set() -> None:
    assert is_high_severity(AuthEventType.LOGIN_BREAK_GLASS_USED)
    assert is_high_severity(AuthEventType.OIDC_REFRESH_REUSE_DETECTED)
    assert is_high_severity("session.stale_ip")
    assert not is_high_severity(AuthEventType.LOGIN_PASSWORD_SUCCESS)
    assert not is_high_severity("oidc.token.issued")


def test_fmt_auth_event_projects_and_flags() -> None:
    row = AuthEvent(
        event_type="login.break_glass.used",
        source_ip="10.0.0.1",
        success=True,
        detail={"credential": "break-glass"},
    )
    row.id = 7
    row.ts = datetime(2026, 7, 2, tzinfo=UTC)
    rec = _fmt_auth_event(row)
    assert rec["stream"] == "auth_events"
    assert rec["severity"] == "high"
    assert rec["source_ip"] == "10.0.0.1"
    assert rec["ts"].startswith("2026-07-02")


def test_fmt_audit_log_denies_are_high() -> None:
    row = AuditLog(decision="deny", reason="default_deny", source_ip="10.0.0.2")
    row.id = 3
    row.ts = datetime(2026, 7, 2, tzinfo=UTC)
    rec = _fmt_audit_log(row)
    assert rec["severity"] == "high" and rec["decision"] == "deny"

    allow = AuditLog(decision="allow", source_ip="10.0.0.2")
    allow.id = 4
    allow.ts = datetime(2026, 7, 2, tzinfo=UTC)
    assert _fmt_audit_log(allow)["severity"] == "normal"
