package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"hyproxy/dataplane/internal/authz"
	"hyproxy/dataplane/internal/config"
)

type fakeAuthz struct {
	resp    authz.CheckResponse
	err     error
	lastReq authz.CheckRequest
}

func (f *fakeAuthz) Check(_ context.Context, req authz.CheckRequest) (authz.CheckResponse, error) {
	f.lastReq = req
	return f.resp, f.err
}

type captured struct {
	header http.Header
	host   string
	path   string
}

func newBackend(t *testing.T) (*httptest.Server, *captured) {
	t.Helper()
	cap := &captured{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.header = r.Header.Clone()
		cap.host = r.Host
		cap.path = r.URL.Path
		_, _ = io.WriteString(w, "backend-ok")
	}))
	t.Cleanup(backend.Close)
	return backend, cap
}

func newServer(t *testing.T, backendURL string, checker AuthzChecker) *Server {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0", TLSCert: "c", TLSKey: "k",
		AuthzURL: "http://127.0.0.1:1", AuthHost: "auth.local.test",
		AuthBackend: backendURL,
		Routes: map[string]config.Route{
			"app.local.test": {Backend: backendURL},
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

func doReq(s *Server, method, host, path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://placeholder"+path, nil)
	req.Host = host
	req.RemoteAddr = "203.0.113.9:52011"
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestUnknownHostGets421(t *testing.T) {
	backend, _ := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{})
	for _, host := range []string{"ghost.local.test", "", "bad host", "[::1]:443"} {
		rec := doReq(s, http.MethodGet, host, "/", nil)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("host %q: got %d, want 421", host, rec.Code)
		}
		if body := rec.Body.String(); strings.TrimSpace(body) != "" {
			t.Fatalf("unknown host response leaked content: %q", body)
		}
	}
}

func TestAllowInjectsIdentityAndStripsSpoofedHeaders(t *testing.T) {
	backend, cap := newBackend(t)
	checker := &fakeAuthz{resp: authz.CheckResponse{
		Decision: "allow",
		Headers: map[string]string{
			"X-Forwarded-User": "user@example.test",
			"X-Auth-User-Id":   "user-1",
			"X-Auth-Roles":     "media",
		},
	}}
	s := newServer(t, backend.URL, checker)

	rec := doReq(s, http.MethodGet, "app.local.test", "/photos?a=1", func(r *http.Request) {
		r.Header.Set("X-Forwarded-User", "admin@evil.test") // spoof attempt
		r.Header.Set("X-Auth-Roles", "admin")
		r.Header.Set("X-Forwarded-For", "10.0.0.1") // spoof attempt
		r.AddCookie(&http.Cookie{Name: "__Secure-gw", Value: "gw.secret"})
		r.AddCookie(&http.Cookie{Name: "app_pref", Value: "dark"})
	})
	if rec.Code != http.StatusOK || rec.Body.String() != "backend-ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if got := cap.header.Get("X-Forwarded-User"); got != "user@example.test" {
		t.Fatalf("X-Forwarded-User = %q", got)
	}
	if got := cap.header.Get("X-Auth-Roles"); got != "media" {
		t.Fatalf("X-Auth-Roles = %q", got)
	}
	if got := cap.header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For = %q (spoof must not pass)", got)
	}
	if got := cap.header.Get("X-Forwarded-Host"); got != "app.local.test" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	cookieHeader := cap.header.Get("Cookie")
	if strings.Contains(cookieHeader, "__Secure-gw") {
		t.Fatalf("gateway cookie leaked upstream: %q", cookieHeader)
	}
	if !strings.Contains(cookieHeader, "app_pref=dark") {
		t.Fatalf("app cookies must survive: %q", cookieHeader)
	}
	if checker.lastReq.GatewayCookie != "gw.secret" {
		t.Fatalf("authz did not receive the gateway cookie: %+v", checker.lastReq)
	}
	if checker.lastReq.URI != "/photos?a=1" || checker.lastReq.SourceIP != "203.0.113.9" {
		t.Fatalf("authz request wrong: %+v", checker.lastReq)
	}
}

func TestDenyIs403(t *testing.T) {
	backend, cap := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "deny"}})
	rec := doReq(s, http.MethodGet, "app.local.test", "/", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if cap.header != nil {
		t.Fatal("backend must not be touched on deny")
	}
}

func TestAuthRequiredRedirectsGetAnd401sPost(t *testing.T) {
	backend, cap := newBackend(t)
	redirect := "https://auth.local.test/gateway/start?rd=x"
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{
		Decision: "auth_required", Redirect: redirect,
	}})
	rec := doReq(s, http.MethodGet, "app.local.test", "/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != redirect {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = doReq(s, http.MethodPost, "app.local.test", "/", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST got %d, want 401", rec.Code)
	}
	if cap.header != nil {
		t.Fatal("backend must not be touched when unauthenticated")
	}
}

func TestAuthzFailureFailsClosed(t *testing.T) {
	backend, cap := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{err: errors.New("connection refused")})
	rec := doReq(s, http.MethodGet, "app.local.test", "/", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if cap.header != nil {
		t.Fatal("backend must not be touched when authz is down")
	}
}

func TestAuthHostOnlyServesGatewayPaths(t *testing.T) {
	backend, cap := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{})
	rec := doReq(s, http.MethodGet, "auth.local.test", "/gateway/start?rd=y", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway path got %d", rec.Code)
	}
	if cap.path != "/gateway/start" {
		t.Fatalf("proxied path = %q", cap.path)
	}
	for _, path := range []string{"/authz/check", "/", "/healthz", "/gateway", "/gatewayx"} {
		rec = doReq(s, http.MethodPost, "auth.local.test", path, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("path %q got %d, want 404 (internal surface must stay internal)", path, rec.Code)
		}
	}
}

func TestBackendURLNeverDerivedFromClient(t *testing.T) {
	backend, cap := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}})
	// Absolute-form request targets and hostile paths must not change the dial target.
	rec := doReq(s, http.MethodGet, "app.local.test", "/photos", func(r *http.Request) {
		r.URL, _ = url.Parse("https://app.local.test/photos")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if cap.path != "/photos" {
		t.Fatalf("path = %q", cap.path)
	}
	u, _ := url.Parse(backend.URL)
	if cap.host != u.Host {
		t.Fatalf("backend saw host %q, want %q", cap.host, u.Host)
	}
}
