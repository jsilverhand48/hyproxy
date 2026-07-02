package routing

import (
	"strings"
	"testing"

	"hyproxy/dataplane/internal/config"
)

func table(t *testing.T) *Table {
	t.Helper()
	cfg := &config.Config{
		Listen: ":8443", TLSCert: "c", TLSKey: "k",
		AuthzURL: "http://127.0.0.1:8500", AuthHost: "auth.local.test",
		AuthBackend: "http://127.0.0.1:8500",
		Routes: map[string]config.Route{
			"app.local.test": {Backend: "http://127.0.0.1:9001"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return NewTable(cfg)
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"app.local.test", "app.local.test", true},
		{"APP.Local.TEST", "app.local.test", true},
		{"app.local.test:443", "app.local.test", true},
		{"app.local.test.", "app.local.test", true},
		{"app.local.test.:8443", "app.local.test", true},
		{"192.0.2.7", "192.0.2.7", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"", "", false},
		{":443", "", false},
		{"app..local.test", "", false},
		{"-bad.local.test", "", false},
		{"bad-.local.test", "", false},
		{"app.local.test:notaport", "", false},
		{"app.local.test:99999999", "", false},
		{"[::1]:443", "", false},
		{"[::1]", "", false},
		{"app_underscore.test", "", false},
		{"host with space", "", false},
		{"evil/../path", "", false},
		{"evil.test/path", "", false},
		{"evil.test?x=1", "", false},
		{"user@evil.test", "", false},
		{strings.Repeat("a", 300), "", false},
		{strings.Repeat("a", 64) + ".test", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeHost(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeHost(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestLookup(t *testing.T) {
	tbl := table(t)
	if _, _, kind := tbl.Lookup("app.local.test:443"); kind != KindApp {
		t.Fatalf("expected app route, got %v", kind)
	}
	if _, host, kind := tbl.Lookup("AUTH.local.test"); kind != KindAuth || host != "auth.local.test" {
		t.Fatalf("expected auth route, got %v %q", kind, host)
	}
	for _, unknown := range []string{"ghost.local.test", "", "app.local.test.evil.com", "[::1]"} {
		if _, _, kind := tbl.Lookup(unknown); kind != KindNone {
			t.Fatalf("expected KindNone for %q, got %v", unknown, kind)
		}
	}
}

func FuzzNormalizeHost(f *testing.F) {
	for _, seed := range []string{
		"app.local.test", "APP.LOCAL.TEST:443", "a.b.c.d.e.", "[::1]:8443",
		"host_with_underscore", "192.0.2.1:80", "evil.test/path?q=1#f",
		"xn--caf-dma.example", strings.Repeat("a.", 130), "\x00\xff", "a:b:c",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		host, ok := NormalizeHost(raw)
		if !ok {
			if host != "" {
				t.Fatalf("rejected input returned non-empty host %q", host)
			}
			return
		}
		// Invariants for accepted hosts.
		if host == "" || len(host) > 253 {
			t.Fatalf("accepted invalid-length host %q", host)
		}
		if host != strings.ToLower(host) {
			t.Fatalf("host not lowercased: %q", host)
		}
		if strings.ContainsAny(host, " /?#@\\:[]") {
			t.Fatalf("dangerous characters survived: %q", host)
		}
		// Idempotence: normalizing again is a no-op.
		again, ok2 := NormalizeHost(host)
		if !ok2 || again != host {
			t.Fatalf("not idempotent: %q -> %q (%v)", host, again, ok2)
		}
	})
}
