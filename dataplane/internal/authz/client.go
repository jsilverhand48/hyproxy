// Package authz is the forward-auth client for the control plane's
// /authz/check decision point. The data plane never decides anything itself;
// it fails closed when the control plane is unreachable.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"hyproxy/dataplane/internal/config"
)

type Client struct {
	base string
	http *http.Client
}

func NewClient(baseURL string) *Client {
	// Every authed proxied request pays a /authz/check round-trip; the
	// default transport keeps only 2 idle conns per host, which forces
	// re-dials under concurrent segment fetches.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 64
	t.MaxIdleConnsPerHost = 64
	return &Client{
		base: baseURL,
		http: &http.Client{Timeout: 5 * time.Second, Transport: t},
	}
}

type CheckRequest struct {
	Host          string `json:"host"`
	Method        string `json:"method"`
	URI           string `json:"uri"`
	SourceIP      string `json:"source_ip"`
	BackendPort   int    `json:"backend_port,omitempty"`
	GatewayCookie string `json:"gateway_cookie,omitempty"`
}

type CheckResponse struct {
	Decision string            `json:"decision"`
	Reason   string            `json:"reason"`
	Headers  map[string]string `json:"headers"`
	Redirect string            `json:"redirect"`
}

func (c *Client) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CheckResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.base+"/authz/check", bytes.NewReader(body),
	)
	if err != nil {
		return CheckResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return CheckResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return CheckResponse{}, fmt.Errorf("authz returned %d", resp.StatusCode)
	}
	var out CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CheckResponse{}, err
	}
	return out, nil
}

// ConsumeRequest authorizes a Guacamole tunnel WebSocket connect: single-use,
// IP-bound, and tied to a live gateway session (so IdP-session revocation tears
// the tunnel down).
type ConsumeRequest struct {
	Token         string `json:"token"`
	SourceIP      string `json:"source_ip"`
	GatewayCookie string `json:"gateway_cookie,omitempty"`
}

type ConsumeResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// ConsumeGuac reports whether the tunnel connect is authorized. It fails closed:
// any transport error or non-2xx/3xx status returns allowed=false with err set
// where relevant. A 403 is a clean deny (allowed=false, err=nil).
func (c *Client) ConsumeGuac(ctx context.Context, req ConsumeRequest) (bool, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.base+"/guac/consume", bytes.NewReader(body),
	)
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var out ConsumeResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return false, err
		}
		return out.Decision == "allow", nil
	}
	// 401/403 are clean denials; anything else is an error (fail closed).
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	return false, fmt.Errorf("guac consume returned %d", resp.StatusCode)
}

// routesResponse mirrors the control plane's GET /authz/routes envelope.
type routesResponse struct {
	Routes map[string]config.Route `json:"routes"`
}

// Routes fetches the DB-driven app route table from the control plane. The data
// plane merges these with its static infra routes and hot-swaps. On any error
// the caller keeps its last-good table (fail-closed: never widen on a bad pull).
func (c *Client) Routes(ctx context.Context) (map[string]config.Route, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/authz/routes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz routes returned %d", resp.StatusCode)
	}
	var out routesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Routes, nil
}
