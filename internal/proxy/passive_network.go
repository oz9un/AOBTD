package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

type passiveRenderDialContextKey struct{}

type passiveRenderDialTarget struct {
	host string
}

type passiveIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type passiveNetworkDialer func(context.Context, string, string) (net.Conn, error)

var nonPublicPassivePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // Shared address space / CGNAT.
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments.
	netip.MustParsePrefix("192.0.2.0/24"),  // Documentation.
	netip.MustParsePrefix("198.18.0.0/15"), // Benchmarking.
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), // Documentation.
	netip.MustParsePrefix("2001:10::/28"),  // ORCHID.
	netip.MustParsePrefix("fec0::/10"),     // Deprecated site-local space.
}

func markPassiveRenderDial(req *http.Request) *http.Request {
	if req == nil || req.URL == nil {
		return req
	}
	target := passiveRenderDialTarget{host: strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))}
	return req.WithContext(context.WithValue(req.Context(), passiveRenderDialContextKey{}, target))
}

func passiveRenderDialTargetFromContext(ctx context.Context) (passiveRenderDialTarget, bool) {
	if ctx == nil {
		return passiveRenderDialTarget{}, false
	}
	target, ok := ctx.Value(passiveRenderDialContextKey{}).(passiveRenderDialTarget)
	return target, ok && target.host != ""
}

// installPassiveRenderNetworkGuard makes passive exceptions bypass configured
// outbound HTTP proxies and pins each connection to an IP that was resolved and
// classified as public immediately before dialing. A hostname that passes the
// lexical guard therefore cannot DNS-rebind the transport onto loopback,
// RFC1918, link-local, metadata, or another special-purpose address.
func installPassiveRenderNetworkGuard(transport *http.Transport) {
	if transport == nil {
		return
	}
	baseDial := transport.DialContext
	if baseDial == nil {
		baseDial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = newPassiveRenderDialContext(net.DefaultResolver, baseDial)

	baseProxy := transport.Proxy
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if _, passive := passiveRenderDialTargetFromContext(req.Context()); passive {
			return nil, nil
		}
		if baseProxy == nil {
			return nil, nil
		}
		return baseProxy(req)
	}
}

func newPassiveRenderDialContext(resolver passiveIPResolver, dial passiveNetworkDialer) passiveNetworkDialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		target, passive := passiveRenderDialTargetFromContext(ctx)
		if !passive {
			return dial(ctx, network, address)
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("passive render dial target: %w", err)
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host != target.host {
			return nil, fmt.Errorf("passive render dial host changed from %q to %q", target.host, host)
		}

		ips, err := resolvePassivePublicIPs(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			pinnedAddress := net.JoinHostPort(ip.String(), port)
			conn, dialErr := dial(ctx, network, pinnedAddress)
			if dialErr != nil {
				lastErr = dialErr
				continue
			}
			peerIP, peerErr := connectionRemoteIP(conn)
			if peerErr != nil || !peerIP.Equal(ip) || !isPublicPassiveIP(peerIP) {
				_ = conn.Close()
				if peerErr != nil {
					lastErr = peerErr
				} else {
					lastErr = fmt.Errorf("passive render dial peer %s did not match pinned public IP %s", peerIP, ip)
				}
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("passive render target %q has no reachable public IP", host)
		}
		return nil, lastErr
	}
}

func resolvePassivePublicIPs(ctx context.Context, resolver passiveIPResolver, host string) ([]net.IP, error) {
	if literal := net.ParseIP(host); literal != nil {
		if !isPublicPassiveIP(literal) {
			return nil, fmt.Errorf("passive render target %q resolved to non-public IP %s", host, literal)
		}
		return []net.IP{literal}, nil
	}
	if resolver == nil {
		return nil, fmt.Errorf("passive render resolver is unavailable")
	}
	resolved, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve passive render target %q: %w", host, err)
	}
	public := make([]net.IP, 0, len(resolved))
	seen := make(map[string]bool)
	for _, candidate := range resolved {
		if !isPublicPassiveIP(candidate.IP) {
			continue
		}
		key := candidate.IP.String()
		if !seen[key] {
			seen[key] = true
			public = append(public, candidate.IP)
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("passive render target %q has no public IP address", host)
	}
	return public, nil
}

func connectionRemoteIP(conn net.Conn) (net.IP, error) {
	if conn == nil || conn.RemoteAddr() == nil {
		return nil, fmt.Errorf("passive render dial returned no remote address")
	}
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcp.IP != nil {
		return tcp.IP, nil
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("passive render dial returned invalid remote address %q", conn.RemoteAddr())
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, fmt.Errorf("passive render dial returned non-IP remote address %q", conn.RemoteAddr())
	}
	return ip, nil
}

func isPublicPassiveIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPassivePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
