package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"hyproxy/dataplane/internal/authz"
	"hyproxy/dataplane/internal/config"
	"hyproxy/dataplane/internal/routing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A DB route added via SwapRoutes becomes live and reverse-proxies to its
// backend without a restart.
func TestSwapRoutesAddsLiveRoute(t *testing.T) {
	backend, _ := newBackend(t)
	checker := &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}}
	s := newServer(t, backend.URL, checker)

	// Unknown before the swap.
	if rec := doReq(s, http.MethodGet, "db.local.test", "/", nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("pre-swap: got %d, want 421", rec.Code)
	}

	if err := s.SwapRoutes(map[string]config.Route{
		"db.local.test": {Backend: backend.URL, BackendPort: 8080},
	}); err != nil {
		t.Fatal(err)
	}

	rec := doReq(s, http.MethodGet, "db.local.test", "/", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "backend-ok" {
		t.Fatalf("post-swap: got %d %q, want 200 backend-ok", rec.Code, rec.Body.String())
	}
	// The policy check saw the DB route's backend port.
	if checker.lastReq.BackendPort != 8080 {
		t.Fatalf("backend port not propagated: got %d", checker.lastReq.BackendPort)
	}
}

// A later swap that drops a route removes it (fail-closed to 421), and static
// infra routes always survive a swap.
func TestSwapRoutesRemovesAndKeepsStatic(t *testing.T) {
	backend, _ := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}})

	_ = s.SwapRoutes(map[string]config.Route{"db.local.test": {Backend: backend.URL}})
	if rec := doReq(s, http.MethodGet, "db.local.test", "/", nil); rec.Code != http.StatusOK {
		t.Fatalf("route should be live: got %d", rec.Code)
	}

	// Empty DB set: the app route disappears...
	_ = s.SwapRoutes(nil)
	if rec := doReq(s, http.MethodGet, "db.local.test", "/", nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("dropped route should 421: got %d", rec.Code)
	}
	// ...but the static infra route (from newServer's config) still serves.
	if rec := doReq(s, http.MethodGet, "app.local.test", "/", nil); rec.Code != http.StatusOK {
		t.Fatalf("static route must survive swap: got %d", rec.Code)
	}
}

// Static infra routes win over a DB route claiming the same host.
func TestStaticRouteWinsOnConflict(t *testing.T) {
	staticBackend, _ := newBackend(t)
	otherBackend, otherCap := newBackend(t)
	s := newServer(t, staticBackend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}})

	// DB tries to redirect the static host to a different backend.
	_ = s.SwapRoutes(map[string]config.Route{"app.local.test": {Backend: otherBackend.URL}})
	_ = doReq(s, http.MethodGet, "app.local.test", "/", nil)
	if otherCap.path != "" {
		t.Fatal("DB route overrode a static infra route; static must win")
	}
}

// A DB route with an unparseable backend is skipped, not fatal; good routes in
// the same swap still install.
func TestSwapSkipsBadBackendKeepsGood(t *testing.T) {
	backend, _ := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}})

	if err := s.SwapRoutes(map[string]config.Route{
		"good.local.test": {Backend: backend.URL},
		"bad.local.test":  {Backend: "://not a url"},
	}); err != nil {
		t.Fatalf("swap should tolerate one bad route: %v", err)
	}
	if rec := doReq(s, http.MethodGet, "good.local.test", "/", nil); rec.Code != http.StatusOK {
		t.Fatalf("good route should serve: got %d", rec.Code)
	}
	if rec := doReq(s, http.MethodGet, "bad.local.test", "/", nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("bad route should be absent (421): got %d", rec.Code)
	}
}

// Concurrent swaps and lookups must not race (run with -race).
func TestConcurrentSwapAndLookup(t *testing.T) {
	backend, _ := newBackend(t)
	s := newServer(t, backend.URL, &fakeAuthz{resp: authz.CheckResponse{Decision: "allow"}})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = s.SwapRoutes(map[string]config.Route{"db.local.test": {Backend: backend.URL}})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			rs := s.routes.Load()
			_, _, _ = rs.table.Lookup("db.local.test")
		}
	}()
	wg.Wait()
}

// Guac DB routes (no backend of their own) resolve to the configured guac
// backend; without one they are skipped.
func TestGuacDBRouteUsesConfiguredBackend(t *testing.T) {
	guacBackend, _ := newBackend(t)
	cfg := &config.Config{
		Listen: ":0", TLSCert: "c", TLSKey: "k",
		AuthzURL: "http://127.0.0.1:1", AuthHost: "auth.local.test",
		AuthBackend: guacBackend.URL,
		GuacBackend: guacBackend.URL,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, &fakeAuthz{guacAllowed: true}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapRoutes(map[string]config.Route{
		"desktop.local.test": {GuacTunnel: true},
	}); err != nil {
		t.Fatal(err)
	}
	rs := s.routes.Load()
	route, _, kind := rs.table.Lookup("desktop.local.test")
	if kind != routing.KindApp || !route.GuacTunnel {
		t.Fatalf("expected a guac app route, got kind=%v guac=%v", kind, route.GuacTunnel)
	}
	if rs.proxies["desktop.local.test"] == nil {
		t.Fatal("guac route got no proxy despite a configured guac backend")
	}
}
