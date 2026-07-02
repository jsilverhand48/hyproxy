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
)

type Client struct {
	base string
	http *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		base: baseURL,
		http: &http.Client{Timeout: 5 * time.Second},
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
