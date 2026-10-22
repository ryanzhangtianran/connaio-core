package reverse

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/ssh"
	"github.com/stretchr/testify/require"
)

func TestSSHTunnel(t *testing.T) {
	echo := startEcho(t)
	server := startSSHServer(t)
	remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))

	cfg := map[string]any{
		"name": "ssh-test", "type": "ssh",
		"server": "127.0.0.1", "port": portOf(t, server),
		"username": "u", "password": "pw",
		"forwards": []any{map[string]any{"remote": remote, "local": echo}},
	}
	tn := startTunnel(t)
	tun, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{tun})
	defer Patch(nil)
	requireEcho(t, remote)
	requireRejectedByRule(t, "IN-NAME", "ssh-test", remote)
	require.Equal(t, StateRunning, Statuses()[0].State)

	// a reload keeps an unchanged tunnel's session and restarts a changed one
	before := active["ssh-test"]
	same, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{same})
	require.Same(t, before, active["ssh-test"])
	cfg["username"] = "u2"
	changed, err := Parse(cfg, tn)
	require.NoError(t, err)
	Patch([]*Tunnel{changed})
	require.NotSame(t, before, active["ssh-test"])
}

// TestDisabledTunnel: a tunnel disabled in the config is listed as stopped and not run; enabling it
// again starts it.
func TestDisabledTunnel(t *testing.T) {
	echo := startEcho(t)
	server := startSSHServer(t)
	remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	cfg := map[string]any{
		"name": "ssh-off", "type": "ssh", "disabled": true,
		"server": "127.0.0.1", "port": portOf(t, server),
		"username": "u", "password": "pw",
		"forwards": []any{map[string]any{"remote": remote, "local": echo}},
	}
	tun, err := Parse(cfg, startTunnel(t))
	require.NoError(t, err)
	Patch([]*Tunnel{tun})
	defer Patch(nil)
	require.Equal(t, StateStopped, Statuses()[0].State)
	_, err = net.DialTimeout("tcp", remote, time.Second)
	require.Error(t, err, "a stopped tunnel must not listen on the server")

	cfg["disabled"] = false
	on, err := Parse(cfg, startTunnel(t))
	require.NoError(t, err)
	Patch([]*Tunnel{on})
	requireEcho(t, remote)
}

func TestParseErrors(t *testing.T) {
	for name, mapping := range map[string]map[string]any{
		"no name":         {"type": "ssh"},
		"bad type":        {"name": "x", "type": "nope"},
		"ssh no forwards": {"name": "x", "type": "ssh", "server": "h", "port": 22, "username": "u"},
		"ssh bad forward": {"name": "x", "type": "ssh", "server": "h", "port": 22, "username": "u", "forwards": []any{map[string]any{"remote": "8080", "local": "127.0.0.1:80"}}},
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

// requireRejectedByRule proves reverse traffic is routed by rules: <ruleType>,<payload>,REJECT must cut it off.
func requireRejectedByRule(t *testing.T, ruleType, payload, addr string) {
	rule, err := rules.ParseRule(ruleType, payload, "REJECT", nil, nil)
	require.NoError(t, err)
	tunnel.UpdateRules([]C.Rule{rule}, nil, nil)
	defer tunnel.UpdateRules(nil, nil, nil)

	c, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("ping"))
	_, err = io.ReadFull(c, make([]byte, 4))
	require.Error(t, err)
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

// requireEcho retries until addr echoes back, since tunnels come up asynchronously.
func requireEcho(t *testing.T, addr string) {
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return false
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(c, buf)
		return err == nil && string(buf) == "ping"
	}, 20*time.Second, 200*time.Millisecond)
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func portOf(t *testing.T, addr string) int {
	_, p, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(p)
	require.NoError(t, err)
	return port
}

// startSSHServer runs a minimal sshd that only supports password auth and tcpip-forward (ssh -R).
func startSSHServer(t *testing.T) string {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "pw" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHConn(c, cfg)
		}
	}()
	return ln.Addr().String()
}

func serveSSHConn(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "")
		}
	}()
	for req := range reqs {
		if req.Type != "tcpip-forward" {
			req.Reply(false, nil)
			continue
		}
		var fwd struct {
			Addr string
			Port uint32
		}
		if ssh.Unmarshal(req.Payload, &fwd) != nil {
			req.Reply(false, nil)
			continue
		}
		rl, err := net.Listen("tcp", net.JoinHostPort(fwd.Addr, strconv.Itoa(int(fwd.Port))))
		if err != nil {
			req.Reply(false, nil)
			continue
		}
		req.Reply(true, nil)
		go func() { sc.Wait(); rl.Close() }()
		go func() {
			for {
				rc, err := rl.Accept()
				if err != nil {
					return
				}
				orig := rc.RemoteAddr().(*net.TCPAddr)
				payload := ssh.Marshal(struct {
					Addr  string
					Port  uint32
					OAddr string
					OPort uint32
				}{fwd.Addr, fwd.Port, orig.IP.String(), uint32(orig.Port)})
				ch, creqs, err := sc.OpenChannel("forwarded-tcpip", payload)
				if err != nil {
					rc.Close()
					continue
				}
				go ssh.DiscardRequests(creqs)
				go func() { io.Copy(ch, rc); ch.CloseWrite() }()
				go func() { io.Copy(rc, ch); rc.Close() }()
			}
		}()
	}
}
