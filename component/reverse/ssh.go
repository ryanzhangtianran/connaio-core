package reverse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

const sshKeepAlive = 30 * time.Second

// sshKeepAliveMax is how many keepalives in a row may go unanswered before the session counts as
// dead, as OpenSSH's ServerAliveCountMax: a reply queues behind whatever the session carries, and
// under a long transfer on a slow link one can take longer than an interval.
const sshKeepAliveMax = 4

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
		t.retry(ctx, func(ctx context.Context, up func()) error {
			return serveSSH(ctx, t.Name, out, opt.Forwards, tunnel, up)
		})
	}
	t.detail = func(s *Status) { // one session carries all forwards, so they share the tunnel state
		for _, f := range opt.Forwards {
			s.Forwards = append(s.Forwards, ForwardStatus{Remote: f.Remote, Local: f.Local})
		}
	}
	return nil
}

// serveSSH holds one SSH session with all forwards until the session dies or ctx is done.
func serveSSH(ctx context.Context, name string, out *outbound.Ssh, forwards []sshForward, tunnel C.Tunnel, up func()) error {
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
			return fmt.Errorf("keepalive: no reply in %s", sshKeepAlive*sshKeepAliveMax)
		}
		go func() { // waits for its reply without holding up the next tick; ends when the client closes
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err == nil {
				unanswered.Store(0)
			}
		}()
	}
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
