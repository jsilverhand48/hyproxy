package botfilter

import (
	"context"
	"errors"
	"net"
	"regexp"
	"testing"
	"time"
)

// fakeMMDB fills the botfilter record structs from a per-IP map. A missing IP
// leaves the record zero-valued (mirrors maxminddb's "not found" behavior).
type fakeMMDB struct {
	asn     map[string]uint
	country map[string]string
}

func (f *fakeMMDB) Lookup(ip net.IP, result any) error {
	switch r := result.(type) {
	case *asnRecord:
		if v, ok := f.asn[ip.String()]; ok {
			r.ASN = v
		}
	case *countryRecord:
		if v, ok := f.country[ip.String()]; ok {
			r.Country.ISOCode = v
		}
	}
	return nil
}

func (f *fakeMMDB) Close() error { return nil }

type fakeResolver struct {
	byIP map[string][]string
	err  error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byIP[addr], nil
}

// newTestFilter builds a Filter directly (bypassing New, which needs real
// .mmdb files) so Decide can be exercised against fakes.
func newTestFilter(f *Filter) *Filter {
	if f.blockedASNs == nil {
		f.blockedASNs = map[uint]struct{}{}
	}
	if f.blockedCountries == nil {
		f.blockedCountries = map[string]struct{}{}
	}
	f.cache = newVerdictCache(time.Minute)
	return f
}

func TestDecide(t *testing.T) {
	badUA := regexp.MustCompile(`(?i)(bot|crawler|python-requests|curl)`)
	const cleanIP = "203.0.113.7"     // residential, no PTR, benign ASN/country
	const cloudIP = "198.51.100.10"   // ASN 16509, US
	const hostingIP = "198.51.100.20" // PTR under amazonaws.com

	mmdb := &fakeMMDB{
		asn:     map[string]uint{cloudIP: 16509, hostingIP: 14618},
		country: map[string]string{cloudIP: "US", hostingIP: "US"},
	}
	res := &fakeResolver{byIP: map[string][]string{
		hostingIP: {"ec2-198-51-100-20.compute-1.amazonaws.com."},
		cleanIP:   nil,
	}}

	cases := []struct {
		name        string
		filter      *Filter
		ip          string
		ua          string
		wantBlocked bool
		wantReason  string
	}{
		{
			name:        "bad user-agent blocked",
			filter:      newTestFilter(&Filter{uaPatterns: []*regexp.Regexp{badUA}}),
			ip:          cleanIP,
			ua:          "python-requests/2.31.0",
			wantBlocked: true,
			wantReason:  "bad_user_agent",
		},
		{
			name:        "empty user-agent blocked when enabled",
			filter:      newTestFilter(&Filter{blockEmptyUA: true}),
			ip:          cleanIP,
			ua:          "   ",
			wantBlocked: true,
			wantReason:  "bad_user_agent",
		},
		{
			name:        "empty user-agent allowed when disabled",
			filter:      newTestFilter(&Filter{uaPatterns: []*regexp.Regexp{badUA}}),
			ip:          cleanIP,
			ua:          "",
			wantBlocked: false,
		},
		{
			name: "blocked ASN",
			filter: newTestFilter(&Filter{
				blockedASNs: map[uint]struct{}{16509: {}},
				asnDB:       mmdb,
			}),
			ip:          cloudIP,
			ua:          "Mozilla/5.0",
			wantBlocked: true,
			wantReason:  "blocked_asn",
		},
		{
			name: "blocked country",
			filter: newTestFilter(&Filter{
				blockedCountries: map[string]struct{}{"US": {}},
				countryDB:        mmdb,
			}),
			ip:          cloudIP,
			ua:          "Mozilla/5.0",
			wantBlocked: true,
			wantReason:  "blocked_geo",
		},
		{
			name: "blocked PTR suffix",
			filter: newTestFilter(&Filter{
				ptrSuffixes: []string{"amazonaws.com"},
				resolver:    res,
			}),
			ip:          hostingIP,
			ua:          "Mozilla/5.0",
			wantBlocked: true,
			wantReason:  "blocked_ptr",
		},
		{
			name: "PTR resolver error fails open",
			filter: newTestFilter(&Filter{
				ptrSuffixes: []string{"amazonaws.com"},
				resolver:    &fakeResolver{err: errors.New("timeout")},
			}),
			ip:          hostingIP,
			ua:          "Mozilla/5.0",
			wantBlocked: false,
		},
		{
			name: "clean residential IP allowed",
			filter: newTestFilter(&Filter{
				blockedASNs:      map[uint]struct{}{16509: {}},
				blockedCountries: map[string]struct{}{"CN": {}},
				ptrSuffixes:      []string{"amazonaws.com"},
				asnDB:            mmdb,
				countryDB:        mmdb,
				resolver:         res,
			}),
			ip:          cleanIP,
			ua:          "Mozilla/5.0",
			wantBlocked: false,
		},
		{
			name: "block any resolvable PTR",
			filter: newTestFilter(&Filter{
				blockAnyPTR: true,
				resolver:    res,
			}),
			ip:          hostingIP,
			ua:          "Mozilla/5.0",
			wantBlocked: true,
			wantReason:  "blocked_ptr",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := tc.filter.Decide(tc.ip, tc.ua)
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked = %v, want %v (reason %q)", blocked, tc.wantBlocked, reason)
			}
			if tc.wantBlocked && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
