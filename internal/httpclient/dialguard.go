// Dial guard: DNS/address safety for the controlled HTTP client (v0.5.0
// scope & safety hardening).
//
// Invariants:
//   - Link-local unicast addresses (IPv4 169.254.0.0/16 — including the
//     cloud-metadata endpoint 169.254.169.254 — and IPv6 fe80::/10) are
//     refused unconditionally, regardless of scope configuration. This
//     defeats DNS-rebinding tricks that try to steer OWNTRACE at instance-
//     metadata endpoints.
//   - Other address classes (loopback, RFC1918) are the operator's explicit
//     choice: authorized internal testing legitimately targets private
//     addresses, so they are governed by the configured scope, not here.
//   - Hostnames are re-resolved per dial and every resolved address is
//     checked, so a mid-scan rebinding cannot bypass the check.
package httpclient

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// LookupFunc resolves a hostname to IP addresses (injectable for tests).
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// defaultLookup wraps net.DefaultResolver.
func defaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// dialGuard validates resolved addresses before connecting.
type dialGuard struct {
	lookup LookupFunc
	dialer *net.Dialer
}

func newDialGuard(lookup LookupFunc) *dialGuard {
	if lookup == nil {
		lookup = defaultLookup
	}
	return &dialGuard{lookup: lookup, dialer: &net.Dialer{Timeout: 10 * time.Second}}
}

// isForbiddenIP reports addresses OWNTRACE must never contact.
func isForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4 link-local (includes cloud metadata 169.254.169.254).
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	// IPv6 link-local fe80::/10.
	if ip.To16() != nil && ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// DialContext resolves, validates and dials. The hostname is dialed via the
// resolved IP while preserving the original address string format.
func (g *dialGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial guard: bad address %q: %w", addr, err)
	}
	// IP-literal targets are validated directly.
	if ip := net.ParseIP(host); ip != nil {
		if isForbiddenIP(ip) {
			return nil, fmt.Errorf("dial guard: refusing forbidden address %s (link-local/metadata endpoints are never contacted)", host)
		}
		return g.dialer.DialContext(ctx, network, addr)
	}
	ips, err := g.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial guard: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dial guard: no addresses for %s", host)
	}
	var lastErr error
	for _, ip := range ips {
		if isForbiddenIP(ip) {
			lastErr = fmt.Errorf("dial guard: host %s resolved to forbidden address %s (link-local/metadata endpoints are never contacted)", host, ip.String())
			continue
		}
		conn, derr := g.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr != nil {
		if strings.Contains(lastErr.Error(), "forbidden address") {
			return nil, lastErr
		}
		return nil, fmt.Errorf("dial guard: dial %s: %w", host, lastErr)
	}
	return nil, fmt.Errorf("dial guard: no permitted address for %s", host)
}
