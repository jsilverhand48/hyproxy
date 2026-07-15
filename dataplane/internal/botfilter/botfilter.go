// Package botfilter drops automated/bot traffic at the edge using two
// independent signals: a User-Agent denylist (evaluated per request) and a
// source-IP network-reputation check (cloud/hosting ASN, geo country, and
// reverse-DNS suffix), the latter cached per source IP. A Filter is built once
// at startup from the data-plane config and is safe for concurrent use.
//
// The IP signals are a "does this look like datacenter, not residential"
// heuristic: an IP whose ASN is a cloud provider, or that reverse-resolves to a
// hosting domain, is almost never a real browser client. See BlockAnyResolvablePTR
// for the caveat that many residential ISPs also assign PTR records.
package botfilter

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"hyproxy/dataplane/internal/config"
)

// ptrLookupTimeout bounds the reverse-DNS query so a slow or unresponsive
// resolver never stalls a request; on timeout the PTR signal fails open.
const ptrLookupTimeout = 2 * time.Second

// mmdbReader is the slice of the maxminddb API botfilter needs, abstracted so
// tests can inject fakes without real .mmdb files. *maxminddb.Reader satisfies it.
type mmdbReader interface {
	Lookup(ip net.IP, result any) error
	Close() error
}

// resolver is the slice of net.Resolver botfilter needs, abstracted for tests.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// asnRecord and countryRecord are the fields botfilter reads from the GeoLite2
// ASN and Country databases. Named (not anonymous) so tests can populate them.
type asnRecord struct {
	ASN uint `maxminddb:"autonomous_system_number"`
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type Filter struct {
	// UA signal (per request, never cached).
	uaPatterns   []*regexp.Regexp
	blockEmptyUA bool

	// IP signals (cached per source IP).
	blockedASNs      map[uint]struct{}
	ptrSuffixes      []string // lowercased, no leading dot
	blockAnyPTR      bool
	blockedCountries map[string]struct{} // uppercase ISO codes

	asnDB     mmdbReader // nil unless blockedASNs is non-empty
	countryDB mmdbReader // nil unless blockedCountries is non-empty
	resolver  resolver

	cache *verdictCache
}

// New builds a Filter from cfg, opening the configured MaxMind databases and
// compiling the User-Agent patterns. It returns (nil, nil) when no bot-filter
// signal is configured at all, so the feature stays entirely off. Callers must
// Close the returned Filter (when non-nil) to release the mmdb readers.
func New(cfg *config.Config) (*Filter, error) {
	f := &Filter{
		blockEmptyUA:     cfg.BlockEmptyUserAgent,
		blockAnyPTR:      cfg.BlockAnyResolvablePTR,
		blockedASNs:      make(map[uint]struct{}, len(cfg.BlockedASNs)),
		blockedCountries: make(map[string]struct{}, len(cfg.BlockedCountries)),
		resolver:         net.DefaultResolver,
	}
	for _, pat := range cfg.BlockedUserAgents {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("blocked_user_agents %q: %w", pat, err)
		}
		f.uaPatterns = append(f.uaPatterns, re)
	}
	for _, asn := range cfg.BlockedASNs {
		f.blockedASNs[asn] = struct{}{}
	}
	for _, s := range cfg.BlockedPTRSuffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, ".")
		if s != "" {
			f.ptrSuffixes = append(f.ptrSuffixes, s)
		}
	}
	for _, c := range cfg.BlockedCountries {
		f.blockedCountries[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}

	if len(f.blockedASNs) > 0 {
		r, err := maxminddb.Open(cfg.GeoIPASNDB)
		if err != nil {
			return nil, fmt.Errorf("geoip_asn_db: %w", err)
		}
		f.asnDB = r
	}
	if len(f.blockedCountries) > 0 {
		r, err := maxminddb.Open(cfg.GeoIPCountryDB)
		if err != nil {
			if f.asnDB != nil {
				_ = f.asnDB.Close()
			}
			return nil, fmt.Errorf("geoip_country_db: %w", err)
		}
		f.countryDB = r
	}

	if !f.uaChecksEnabled() && !f.ipChecksEnabled() {
		// Nothing configured: no filter, no readers were opened.
		return nil, nil
	}
	f.cache = newVerdictCache(time.Duration(cfg.BotFilterCacheTTLSecs) * time.Second)
	return f, nil
}

func (f *Filter) uaChecksEnabled() bool {
	return len(f.uaPatterns) > 0 || f.blockEmptyUA
}

func (f *Filter) ipChecksEnabled() bool {
	return len(f.blockedASNs) > 0 || len(f.ptrSuffixes) > 0 || f.blockAnyPTR ||
		len(f.blockedCountries) > 0
}

// Decide reports whether a request from source IP ip with the given User-Agent
// should be dropped, and a short reason for logging. The UA denylist is checked
// first (cheap, per request); the IP-based signals are evaluated only on a UA
// miss and cached per source IP.
func (f *Filter) Decide(ip, userAgent string) (blocked bool, reason string) {
	if f.blockEmptyUA && strings.TrimSpace(userAgent) == "" {
		return true, "bad_user_agent"
	}
	for _, re := range f.uaPatterns {
		if re.MatchString(userAgent) {
			return true, "bad_user_agent"
		}
	}
	if !f.ipChecksEnabled() {
		return false, ""
	}
	now := time.Now()
	if v, ok := f.cache.get(ip, now); ok {
		return v.blocked, v.reason
	}
	v := f.evaluateIP(ip)
	f.cache.put(ip, v, now)
	return v.blocked, v.reason
}

// evaluateIP runs the source-IP signals cheapest first (local mmdb lookups),
// leaving the network-bound PTR query for last.
func (f *Filter) evaluateIP(ip string) verdict {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return verdict{}
	}
	if f.asnDB != nil {
		var rec asnRecord
		if err := f.asnDB.Lookup(parsed, &rec); err == nil {
			if _, bad := f.blockedASNs[rec.ASN]; bad {
				return verdict{blocked: true, reason: "blocked_asn"}
			}
		}
	}
	if f.countryDB != nil {
		var rec countryRecord
		if err := f.countryDB.Lookup(parsed, &rec); err == nil {
			if _, bad := f.blockedCountries[strings.ToUpper(rec.Country.ISOCode)]; bad {
				return verdict{blocked: true, reason: "blocked_geo"}
			}
		}
	}
	if f.blockAnyPTR || len(f.ptrSuffixes) > 0 {
		if f.ptrBlocked(parsed) {
			return verdict{blocked: true, reason: "blocked_ptr"}
		}
	}
	return verdict{}
}

// ptrBlocked reports whether ip's reverse-DNS name triggers a block. It fails
// open (returns false) on any resolver error or empty result: a DNS hiccup must
// never block a legitimate user, and the ASN/geo signals have already run.
func (f *Filter) ptrBlocked(ip net.IP) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ptrLookupTimeout)
	defer cancel()
	names, err := f.resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return false
	}
	if f.blockAnyPTR {
		return true
	}
	for _, name := range names {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		for _, suffix := range f.ptrSuffixes {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
}

// Close releases the MaxMind readers. Safe to call on a nil Filter.
func (f *Filter) Close() error {
	if f == nil {
		return nil
	}
	var firstErr error
	for _, r := range []mmdbReader{f.asnDB, f.countryDB} {
		if r == nil {
			continue
		}
		if err := r.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
