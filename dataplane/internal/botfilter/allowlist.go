package botfilter

// Allowlist: source addresses that are never dropped, whatever the UA, ASN,
// geo, and PTR signals say.
//
// The case that forces this to exist: a client behind the proxy that leaves
// through the WAN and comes back in by the public name (hairpin NAT) arrives
// with a source address of the deployment's OWN public IP, i.e. the A record
// of the proxied domain. That address belongs to a residential ISP, so it has
// a PTR record, so with block_any_resolvable_ptr on the edge drops it and the
// site blocks its own users. The addresses of the configured public hostnames
// are therefore resolved at startup, refreshed periodically (a residential WAN
// address moves on lease renewal), and exempted. Private and loopback sources,
// where a hairpinning router that SNATs to its inside address lands, are
// exempt for the same reason.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"hyproxy/dataplane/internal/config"
)

const (
	// selfIPRefreshInterval is how often the deployment's own hostnames are
	// re-resolved: dynamic WAN addresses change without notice, and a stale
	// entry means dropping our own users again.
	selfIPRefreshInterval = 5 * time.Minute
	// selfIPLookupTimeout bounds one full refresh pass over all hostnames.
	selfIPLookupTimeout = 5 * time.Second
)

// alwaysAllowedCIDRs are source networks that cannot be internet bots:
// loopback, RFC1918 private, CGNAT (carrier or Tailscale), link-local, and
// IPv6 unique-local. Their PTR records point at internal or ISP-owned names,
// which the reputation signals would happily block.
var alwaysAllowedCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// hostResolver is the slice of net.Resolver used to resolve this deployment's
// own public hostnames, kept separate from resolver (PTR lookups) so either
// can be faked independently in tests.
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// buildAllowNets returns the always-allowed private networks plus the
// operator-configured botfilter_allow_cidrs.
func buildAllowNets(extra []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(alwaysAllowedCIDRs)+len(extra))
	for _, cidr := range alwaysAllowedCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("internal allow cidr %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	for _, cidr := range extra {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("botfilter_allow_cidrs %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// publicHosts is every hostname this deployment answers to that is known at
// startup: the auth host and the static infra routes. DB-driven app routes are
// subdomains of the same domain and resolve to the same public address, so
// they add nothing to the resolved set.
func publicHosts(cfg *config.Config) []string {
	seen := make(map[string]struct{}, len(cfg.Routes)+1)
	var hosts []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if _, dup := seen[h]; dup {
			return
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	add(cfg.AuthHost)
	for host := range cfg.Routes {
		add(host)
	}
	return hosts
}

// allowed reports whether ip bypasses every bot signal: one of this
// deployment's own public addresses, a private/loopback source, or an
// operator-configured allow CIDR.
func (f *Filter) allowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if ips := f.selfIPs.Load(); ips != nil {
		for _, self := range *ips {
			if self.Equal(parsed) {
				return true
			}
		}
	}
	for _, n := range f.allowNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// startSelfRefresh resolves the deployment's own hostnames once,
// synchronously, so the allowlist is populated before the listener accepts
// anything, then keeps them fresh in the background until Close.
func (f *Filter) startSelfRefresh() {
	if len(f.selfHosts) == 0 {
		return
	}
	f.refreshSelfIPs()
	f.stopSelf = make(chan struct{})
	f.selfDone = make(chan struct{})
	go func() {
		defer close(f.selfDone)
		t := time.NewTicker(selfIPRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-f.stopSelf:
				return
			case <-t.C:
				f.refreshSelfIPs()
			}
		}
	}()
}

// refreshSelfIPs re-resolves every public hostname and swaps in the result. A
// pass that resolves nothing keeps the previous addresses: dropping the
// allowlist because DNS blipped would start blocking our own users, which is
// the exact failure this guards against.
func (f *Filter) refreshSelfIPs() {
	ctx, cancel := context.WithTimeout(context.Background(), selfIPLookupTimeout)
	defer cancel()
	var ips []net.IP
	for _, host := range f.selfHosts {
		addrs, err := f.ipResolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if !containsIP(ips, a.IP) {
				ips = append(ips, a.IP)
			}
		}
	}
	if len(ips) == 0 {
		return
	}
	f.selfIPs.Store(&ips)
}

// stopSelfRefresh halts the background refresh and waits for it to exit.
func (f *Filter) stopSelfRefresh() {
	if f.stopSelf == nil {
		return
	}
	close(f.stopSelf)
	<-f.selfDone
	f.stopSelf = nil
}

// SelfIPs returns the currently resolved public addresses of this deployment,
// for startup logging and diagnostics.
func (f *Filter) SelfIPs() []string {
	if f == nil {
		return nil
	}
	ips := f.selfIPs.Load()
	if ips == nil {
		return nil
	}
	out := make([]string, 0, len(*ips))
	for _, ip := range *ips {
		out = append(out, ip.String())
	}
	return out
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, cur := range list {
		if cur.Equal(ip) {
			return true
		}
	}
	return false
}
