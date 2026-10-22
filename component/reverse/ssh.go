package reverse

import (
	"context"
	"errors"
	"fmt"
	"github.com/metacubex/ssh"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

const sshKeepAlive = 15 * time.Second

// sshKeepAliveMax is how many keepalives in a row may go unanswered before the session counts as
// dead, as OpenSSH's ServerAliveCountMax: a reply queues behind whatever the session carries, and
// under a long transfer on a slow link one can take longer than an interval.
const sshKeepAliveMax = 3

// errDeadPath is a session that died by its keepalives going unanswered: the server hasn't noticed
// either (sshd's ClientAliveInterval is off by default), so its side still holds the remote ports.
var errDeadPath = errors.New("keepalive: no reply")

// reclaimScript ends the sshd sessions on the server (sshd, or sshd-session since OpenSSH 9.8)
// that listen on the ports given as arguments: the ones a dead session of ours left. ss shows only
// the login user's own processes unless it is root, so other users' are left alone.
// shortcut: Linux servers only (ss); add an lsof fallback if a tunnel's server is a Mac or BSD.
const reclaimScript = `for p in "$@"; do ss -Hltnp "sport = :$p"; done | grep -o '"sshd[^"]*",pid=[0-9]*' | sed 's/.*pid=//' | sort -u | while read -r pid; do kill "$pid" && echo "$pid"; done`

// sshOption reuses the ssh outbound options (auth, host-key, dialer-proxy) plus the -R forwards.
type sshOption struct {
	outbound.SshOption
	Forwards []sshForward `proxy:"forwards"`
}

type sshForward struct {
	Remote string      `proxy:"remote"` // address the SSH server listens on, e.g. 0.0.0.0:8080 (needs GatewayPorts for non-loopback)
	Local  string      `proxy:"local"`  // target routed by rules, e.g. 127.0.0.1:80
	target socks5.Addr `proxy:"-"`
}

func parseSSH(t *Tunnel, mapping map[string]any, tunnel C.Tunnel) error {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := sshOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return err
	}
	if len(opt.Forwards) == 0 {
		return errors.New("forwards is empty")
	}
	for i, f := range opt.Forwards {
		if _, _, err := net.SplitHostPort(f.Remote); err != nil {
			return fmt.Errorf("invalid forward remote %q: %w", f.Remote, err)
		}
		if opt.Forwards[i].target = socks5.ParseAddr(f.Local); opt.Forwards[i].target == nil {
			return fmt.Errorf("invalid forward local %q", f.Local)
		}
	}
	opt.TunnelForAPI = tunnel
	out, err := outbound.NewSsh(opt.SshOption)
	if err != nil {
		return err
	}
	t.DialerProxy = opt.DialerProxy
	t.run = func(ctx context.Context) {
		defer out.Close()
		var last error
		t.retry(ctx, func(ctx context.Context, up func()) error {
			// after a session of ours died unnoticed by the server, its listeners are reclaimed; after a
			// clean close (another machine took the ports over), they are left to it
			last = serveSSH(ctx, t.Name, out, opt.Forwards, tunnel, errors.Is(last, errDeadPath), up)
			return last
		})
	}
	t.detail = func(s *Status) { // one session carries all forwards, so they share the tunnel state
		for _, f := range opt.Forwards {
			s.Forwards = append(s.Forwards, ForwardStatus{Remote: f.Remote, Local: f.Local})
		}
	}
	return nil
}

// serveSSH holds one SSH session with all forwards until the session dies or ctx is done. With
// reclaim, a remote port the server refuses is freed from a dead session of ours first.
func serveSSH(ctx context.Context, name string, out *outbound.Ssh, forwards []sshForward, tunnel C.Tunnel, reclaim bool, up func()) error {
	handshake, cancel := context.WithTimeout(ctx, 30*time.Second)
	client, err := out.Client(handshake)
	cancel()
	if err != nil {
		return err
	}
	defer client.Close() // also closes every remote listener below
	defer context.AfterFunc(ctx, func() { client.Close() })()
	for _, f := range forwards {
		timeout := time.AfterFunc(30*time.Second, func() { client.Close() }) // a server that accepts and then stalls
		ln, err := client.Listen("tcp", f.Remote)
		if err != nil && reclaim {
			reclaim = false
			if n := reclaimPorts(client, forwards); n > 0 {
				log.Infoln("[ReverseTunnel] %s: ended %d dead session(s) of ours on the server", name, n)
				ln, err = client.Listen("tcp", f.Remote)
			}
		}
		timeout.Stop()
		if err != nil {
			return fmt.Errorf("remote listen %s: %w", f.Remote, err)
		}
		go acceptLoop(tunnel, name, ln, f.target)
		log.Infoln("[ReverseTunnel] %s: remote %s -> local %s", name, f.Remote, f.Local)
	}
	up()

	// a connection that breaks shows here at once; one that hangs, by its keepalives going unanswered
	dead := make(chan error, 1)
	go func() { dead <- client.Wait() }()
	var unanswered atomic.Int32
	ticker := time.NewTicker(sshKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-dead:
			return fmt.Errorf("session closed: %w", err)
		case <-ticker.C:
		}
		if unanswered.Add(1) > sshKeepAliveMax {
			return fmt.Errorf("%w in %s", errDeadPath, sshKeepAlive*sshKeepAliveMax)
		}
		go func() { // waits for its reply without holding up the next tick; ends when the client closes
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err == nil {
				unanswered.Store(0)
			}
		}()
	}
}

// reclaimPorts runs reclaimScript for the forwards' remote ports and reports how many sessions it
// ended; a server without ss, or a stalled one, counts as none.
func reclaimPorts(client *ssh.Client, forwards []sshForward) int {
	var ports []string
	for _, f := range forwards {
		if _, p, err := net.SplitHostPort(f.Remote); err == nil {
			ports = append(ports, p)
		}
	}
	session, err := client.NewSession()
	if err != nil {
		return 0
	}
	defer session.Close()
	stall := time.AfterFunc(15*time.Second, func() { session.Close() })
	defer stall.Stop()
	session.Stdin = strings.NewReader(reclaimScript)
	out, err := session.CombinedOutput("sh -s -- " + strings.Join(ports, " "))
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(out)))
}

func acceptLoop(tunnel C.Tunnel, name string, ln net.Listener, target socks5.Addr) {
	for {
		c, err := ln.Accept() // RemoteAddr is the originating user, so SRC-IP rules work
		if err != nil {
			return
		}
		go tunnel.HandleTCPConn(inbound.NewSocket(target, c, C.SSH, inbound.WithInName(name)))
	}
}
