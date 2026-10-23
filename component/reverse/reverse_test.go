package reverse

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/relay"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

// TestWireGuardTunnel: what connects to the relay's port on the server reaches the local service
// behind this end, routed by the rules.
func TestWireGuardTunnel(t *testing.T) {
	cfg, public := startWG(t, "wg-test")
	tn := startTunnel(t)
	tun, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{tun})
	defer Patch(nil)
	requireEcho(t, public)
	require.Eventually(t, func() bool { return Statuses()[0].State == StateRunning }, 5*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool { return Statuses()[0].Relay == relay.Version() }, 10*time.Second, 100*time.Millisecond, "the relay's version, asked through the tunnel")
	requireRejectedByRule(t, public, "IN-NAME", "wg-test")
	requireRejectedByRule(t, public, "IN-TYPE", "WIREGUARD")

	// a client that has sent all it will still gets its answer: the half-close goes through
	c, err := net.DialTimeout("tcp", public, time.Second)
	require.NoError(t, err)
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, c.(*net.TCPConn).CloseWrite())
	got, err := io.ReadAll(c)
	require.NoError(t, err)
	require.Equal(t, "ping", string(got))

	// a reload keeps an unchanged tunnel's device and restarts a changed one
	before := active["wg-test"]
	same, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{same})
	require.Same(t, before, active["wg-test"])
	cfg["persistent-keepalive"] = 10
	changed, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{changed})
	require.NotSame(t, before, active["wg-test"])
	requireEcho(t, public)
}

// TestDisabledTunnel: a tunnel disabled in the config is listed as stopped and not run; enabling it
// again starts it.
func TestDisabledTunnel(t *testing.T) {
	cfg, public := startWG(t, "wg-off")
	cfg["disabled"] = true
	tun, err := Parse(cfg, startTunnel(t))
	require.NoError(t, err)
	Patch([]*Tunnel{tun})
	defer Patch(nil)
	require.Equal(t, StateStopped, Statuses()[0].State)
	c, err := net.DialTimeout("tcp", public, time.Second) // the relay listens, the tunnel behind it is down
	require.NoError(t, err)
	start := time.Now()
	require.False(t, ping(c), "a stopped tunnel must not be reachable")
	require.Less(t, time.Since(start), time.Second, "with Connaio offline the relay closes at once, not after a dial that can only time out")

	cfg["disabled"] = false
	on, err := Parse(cfg, startTunnel(t))
	require.NoError(t, err)
	Patch([]*Tunnel{on})
	requireEcho(t, public)
}

func TestParseErrors(t *testing.T) {
	wg := func(extra map[string]any) map[string]any {
		m := map[string]any{"name": "x", "type": "wireguard", "server": "h", "port": 51820, "ip": "10.9.0.2",
			"private-key": "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "public-key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
			"forwards": []any{map[string]any{"remote": "0.0.0.0:80", "local": "127.0.0.1:80"}}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	_, err := Parse(wg(nil), nil)
	require.NoError(t, err, "the base case must parse")
	for name, mapping := range map[string]map[string]any{
		"no name":        {"type": "wireguard"},
		"bad type":       {"name": "x", "type": "nope"},
		"ssh":            {"name": "x", "type": "ssh", "server": "h", "port": 22, "username": "u"}, // removed
		"no key":         wg(map[string]any{"private-key": nil}),
		"short password": wg(map[string]any{"private-key": nil, "public-key": nil, "password": "1234567"}),
		"bad peer key":   wg(map[string]any{"public-key": "abc="}),
		"no address":     wg(map[string]any{"ip": nil}),
		"no forwards":    wg(map[string]any{"forwards": nil}),
		"host remote":    wg(map[string]any{"forwards": []any{map[string]any{"remote": "vps:80", "local": "127.0.0.1:80"}}}),
		"bad local":      wg(map[string]any{"forwards": []any{map[string]any{"remote": "0.0.0.0:80", "local": "80"}}}),
	} {
		_, err := Parse(mapping, nil)
		require.Error(t, err, name)
	}
}

// startTunnel runs mihomo's tunnel with no rules, so traffic falls through to DIRECT.
func startTunnel(t *testing.T) C.Tunnel {
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}, nil)
	tunnel.UpdateRules(nil, nil, nil)
	tunnel.OnRunning()
	return tunnel.Tunnel
}

// startWG starts a local echo service and a relay as the server, and returns the config of a tunnel
// named name with the relay's password, forwarding the relay's port to the echo service, and that
// port's address.
func startWG(t *testing.T, name string) (map[string]any, string) {
	echo := startEcho(t)
	password := rand.Text()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	public := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- relay.Run(ctx, relay.Config{Password: password, Port: port, Peer: "10.9.0.2", Forwards: []string{public}})
	}()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	require.Eventually(t, func() bool { // listening once its keys are derived
		c, err := net.Dial("tcp", public)
		if err == nil {
			c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)
	return map[string]any{
		"name": name, "type": "wireguard",
		"server": "127.0.0.1", "port": port, "ip": "10.9.0.2", "password": password,
		"forwards": []any{map[string]any{"remote": public, "local": echo}},
	}, public
}

// ping writes through c and reports whether it comes back.
func ping(c net.Conn) bool {
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	_, err := io.ReadFull(c, buf)
	return err == nil && string(buf) == "ping"
}

// requireEcho retries until addr echoes back, since tunnels come up asynchronously.
func requireEcho(t *testing.T, addr string) {
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		return err == nil && ping(c)
	}, 20*time.Second, 200*time.Millisecond)
}

// requireRejectedByRule proves reverse traffic is routed by rules: <ruleType>,<payload>,REJECT must cut it off.
func requireRejectedByRule(t *testing.T, addr, ruleType, payload string) {
	rule, err := rules.ParseRule(ruleType, payload, "REJECT", nil, nil)
	require.NoError(t, err)
	tunnel.UpdateRules([]C.Rule{rule}, nil, nil)
	defer tunnel.UpdateRules(nil, nil, nil)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	require.False(t, ping(c))
}

func startEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestLossyThroughput: over a long lossy link (50ms each way, 1% loss) both ends keep their pace
// with BBR; with CUBIC, which halves it at each loss, they made 2 to 3 Mbit/s.
func TestLossyThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 10s")
	}
	sink, err := net.Listen("tcp", "127.0.0.1:0") // sends forever (d), or takes all it gets (u)
	require.NoError(t, err)
	defer sink.Close()
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				mode := make([]byte, 1)
				io.ReadFull(c, mode)
				if mode[0] == 'd' {
					io.Copy(c, zeros{})
				} else {
					io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	cfg, public := startWG(t, "lossy")
	var largest atomic.Int64
	cfg["port"] = lossyUDP(t, cfg["port"].(int), 50*time.Millisecond, 10, &largest)
	cfg["forwards"] = []any{map[string]any{"remote": public, "local": sink.Addr().String()}}
	tun, err := Parse(cfg, startTunnel(t))
	require.NoError(t, err)
	Patch([]*Tunnel{tun})
	defer Patch(nil)
	require.Eventually(t, func() bool { return Statuses()[0].State == StateRunning }, 20*time.Second, 100*time.Millisecond)

	for mode, least := range map[string]float64{"d": 15, "u": 10} { // Mbit/s; BBR made 69 and 28 here
		c, err := net.Dial("tcp", public)
		require.NoError(t, err)
		c.Write([]byte(mode))
		start := time.Now()
		c.SetDeadline(start.Add(5 * time.Second))
		var n int64
		if mode == "d" {
			n, _ = io.Copy(io.Discard, c)
		} else {
			n, _ = io.Copy(c, zeros{})
		}
		c.Close()
		rate := float64(n) * 8 / time.Since(start).Seconds() / 1e6
		t.Logf("%s: %.1f Mbit/s", mode, rate)
		require.Greater(t, rate, least, map[string]string{"d": "this end sends", "u": "the relay sends"}[mode])
	}
	// both ends keep to relay.MTU: WireGuard adds 32 bytes (its header and tag) to the UDP payload
	require.LessOrEqual(t, largest.Load(), int64(relay.MTU+32), "a WireGuard packet outgrew the tunnel MTU")
}

// lossyUDP relays UDP to port on this machine with delay each way and lossPermille of the packets
// dropped, keeping the largest payload either way in largest, and returns the port it takes them on.
func lossyUDP(t *testing.T, port int, delay time.Duration, lossPermille int64, largest *atomic.Int64) int {
	grow := func(n int) {
		for m := largest.Load(); int64(n) > m && !largest.CompareAndSwap(m, int64(n)); m = largest.Load() {
		}
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	up, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close(); up.Close() })
	drop := func() bool { n, _ := rand.Int(rand.Reader, big.NewInt(1000)); return n.Int64() < lossPermille }
	var client atomic.Pointer[net.Addr]
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			client.Store(&a)
			grow(n)
			if !drop() {
				b := append([]byte(nil), buf[:n]...)
				time.AfterFunc(delay, func() { up.Write(b) })
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			grow(n)
			if a := client.Load(); a != nil && !drop() {
				b := append([]byte(nil), buf[:n]...)
				time.AfterFunc(delay, func() { pc.WriteTo(b, *a) })
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
