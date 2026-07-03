package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckRoundTrip(t *testing.T) {
	var got CheckRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authz/check" || r.Method != http.MethodPost {
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(CheckResponse{
			Decision: "allow",
			Headers:  map[string]string{"X-Forwarded-User": "u@example.test"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.Check(context.Background(), CheckRequest{
		Host: "app.local.test", Method: "GET", URI: "/x?y=1",
		SourceIP: "203.0.113.9", BackendPort: 9001, GatewayCookie: "id.secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" || resp.Headers["X-Forwarded-User"] != "u@example.test" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got.Host != "app.local.test" || got.GatewayCookie != "id.secret" || got.BackendPort != 9001 {
		t.Fatalf("request not marshalled faithfully: %+v", got)
	}
}

func TestRoutesDecodesControlPlaneShape(t *testing.T) {
	// Mirrors the JSON the control plane's GET /authz/routes emits.
	body := `{"routes":{
		"plex.test":{"backend":"https://10.0.0.5:32400","backend_port":32400,"guac_tunnel":false},
		"desktop.test":{"backend":null,"backend_port":0,"guac_tunnel":true}
	}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authz/routes" || r.Method != http.MethodGet {
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	routes, err := NewClient(srv.URL).Routes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := routes["plex.test"]; got.Backend != "https://10.0.0.5:32400" || got.BackendPort != 32400 || got.GuacTunnel {
		t.Fatalf("plex route decoded wrong: %+v", got)
	}
	if got := routes["desktop.test"]; got.Backend != "" || !got.GuacTunnel {
		t.Fatalf("guac route decoded wrong: %+v", got)
	}
}

func TestRoutesNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).Routes(context.Background()); err == nil {
		t.Fatal("expected error on non-200 (fail closed: keep last-good table)")
	}
}

func TestCheckNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).Check(context.Background(), CheckRequest{}); err == nil {
		t.Fatal("expected error on non-200 (fail closed)")
	}
}

func TestCheckConnectionRefusedIsError(t *testing.T) {
	if _, err := NewClient("http://127.0.0.1:1").Check(context.Background(), CheckRequest{}); err == nil {
		t.Fatal("expected error when authz is unreachable")
	}
}
