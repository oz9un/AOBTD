package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type staticPassiveResolver struct {
	addresses map[string][]net.IPAddr
	err       error
}

func (r staticPassiveResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]net.IPAddr(nil), r.addresses[host]...), nil
}

type passiveTestConn struct {
	net.Conn
	remote net.Addr
	closed atomic.Bool
}

func (c *passiveTestConn) RemoteAddr() net.Addr { return c.remote }
func (c *passiveTestConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func TestPassiveRenderDialGuardRejectsPrivateResolutionAndPinsPublicIP(t *testing.T) {
	ctx := context.WithValue(context.Background(), passiveRenderDialContextKey{}, passiveRenderDialTarget{host: "cdn.example.test"})

	var privateDialCalls atomic.Int32
	privateGuard := newPassiveRenderDialContext(staticPassiveResolver{addresses: map[string][]net.IPAddr{
		"cdn.example.test": {{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("10.0.0.8")}},
	}}, func(context.Context, string, string) (net.Conn, error) {
		privateDialCalls.Add(1)
		return nil, errors.New("must not dial")
	})
	if _, err := privateGuard(ctx, "tcp", "cdn.example.test:443"); err == nil || !strings.Contains(err.Error(), "no public IP") {
		t.Fatalf("private DNS result error = %v", err)
	}
	if privateDialCalls.Load() != 0 {
		t.Fatalf("private DNS result reached dialer %d time(s)", privateDialCalls.Load())
	}

	publicIP := net.ParseIP("93.184.216.34")
	var dialAddress string
	publicGuard := newPassiveRenderDialContext(staticPassiveResolver{addresses: map[string][]net.IPAddr{
		"cdn.example.test": {{IP: net.ParseIP("192.168.1.10")}, {IP: publicIP}},
	}}, func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialAddress = address
		return &passiveTestConn{remote: &net.TCPAddr{IP: publicIP, Port: 443}}, nil
	})
	conn, err := publicGuard(ctx, "tcp", "cdn.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil || dialAddress != "93.184.216.34:443" {
		t.Fatalf("dial address/connection = %q/%v", dialAddress, conn)
	}
}

func TestPassiveRenderDialGuardRejectsReboundPeer(t *testing.T) {
	ctx := context.WithValue(context.Background(), passiveRenderDialContextKey{}, passiveRenderDialTarget{host: "cdn.example.test"})
	publicIP := net.ParseIP("93.184.216.34")
	rebound := &passiveTestConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	guard := newPassiveRenderDialContext(staticPassiveResolver{addresses: map[string][]net.IPAddr{
		"cdn.example.test": {{IP: publicIP}},
	}}, func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != "93.184.216.34:443" {
			t.Fatalf("guard did not pin DNS result: %s", address)
		}
		return rebound, nil
	})
	if _, err := guard(ctx, "tcp", "cdn.example.test:443"); err == nil || !strings.Contains(err.Error(), "did not match pinned public IP") {
		t.Fatalf("rebound peer error = %v", err)
	}
	if !rebound.closed.Load() {
		t.Fatal("rebound connection was not closed")
	}
}

func TestPassiveRenderDialGuardDoesNotChangeOrdinaryScopedDial(t *testing.T) {
	var address string
	guard := newPassiveRenderDialContext(staticPassiveResolver{err: errors.New("resolver must not run")},
		func(_ context.Context, _ string, dialAddress string) (net.Conn, error) {
			address = dialAddress
			return &passiveTestConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}}, nil
		})
	if _, err := guard(context.Background(), "tcp", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if address != "127.0.0.1:8080" {
		t.Fatalf("ordinary dial address = %q", address)
	}
}

func TestIsPublicPassiveIPRejectsSpecialPurposeRanges(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1",
	} {
		if isPublicPassiveIP(net.ParseIP(raw)) {
			t.Errorf("special-purpose IP accepted: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublicPassiveIP(net.ParseIP(raw)) {
			t.Errorf("public IP rejected: %s", raw)
		}
	}
}
