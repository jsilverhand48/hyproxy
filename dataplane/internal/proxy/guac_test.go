package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"hyproxy/dataplane/internal/config"
)

func newGuacServer(t *testing.T, backendURL string, checker AuthzChecker) *Server {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0", TLSCert: "c", TLSKey: "k",
		AuthzURL: "http://127.0.0.1:1", AuthHost: "auth.local.test",
		AuthBackend: backendURL,
		Routes: map[string]config.Route{
			"guac.local.test": {Backend: backendURL, GuacTunnel: true},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, checker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGuacTunnelAllowProxiesAndForwardsGrant(t *testing.T) {
	backend, _ := newBackend(t)
	checker := &fakeAuthz{guacAllowed: true}
	s := newGuacServer(t, backend.URL, checker)

	rec := doReq(s, http.MethodGet, "guac.local.test", "/?token=grant-123", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "__Secure-gw", Value: "gw.secret"})
	})
	if rec.Code != http.StatusOK || rec.Body.String() != "backend-ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if checker.lastConsume.Token != "grant-123" {
		t.Fatalf("token not forwarded: %q", checker.lastConsume.Token)
	}
	if checker.lastConsume.SourceIP != "203.0.113.9" {
		t.Fatalf("source ip not forwarded: %q", checker.lastConsume.SourceIP)
	}
	if checker.lastConsume.GatewayCookie != "gw.secret" {
		t.Fatalf("gateway cookie not forwarded: %q", checker.lastConsume.GatewayCookie)
	}
}

func TestGuacTunnelMissingTokenIs401(t *testing.T) {
	backend, _ := newBackend(t)
	s := newGuacServer(t, backend.URL, &fakeAuthz{guacAllowed: true})
	rec := doReq(s, http.MethodGet, "guac.local.test", "/", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestGuacTunnelDeniedIs403(t *testing.T) {
	backend, _ := newBackend(t)
	s := newGuacServer(t, backend.URL, &fakeAuthz{guacAllowed: false})
	rec := doReq(s, http.MethodGet, "guac.local.test", "/?token=x", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestGuacTunnelFailsClosedOn503(t *testing.T) {
	backend, _ := newBackend(t)
	s := newGuacServer(t, backend.URL, &fakeAuthz{guacErr: errors.New("authz down")})
	rec := doReq(s, http.MethodGet, "guac.local.test", "/?token=x", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
}

func TestAuthHostExposesGuacTokenButNotConsume(t *testing.T) {
	backend, _ := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{})

	// /guac/token is browser-facing and proxied to the auth backend.
	tok := doReq(s, http.MethodPost, "auth.local.test", "/guac/token", nil)
	if tok.Code != http.StatusOK {
		t.Fatalf("/guac/token got %d, want 200", tok.Code)
	}
	// /guac/consume is internal only and must never be reachable from clients.
	con := doReq(s, http.MethodPost, "auth.local.test", "/guac/consume", nil)
	if con.Code != http.StatusNotFound {
		t.Fatalf("/guac/consume got %d, want 404", con.Code)
	}
}
