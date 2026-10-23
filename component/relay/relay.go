// Package relay is connaio-relay: the server's end of a reverse tunnel, in user space, without root
// or a WireGuard interface. It takes Connaio's WireGuard handshake on a UDP port and, for each
// forward, listens on the server and carries what connects there through the tunnel to Connaio, at
// its tunnel address on the same port.
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/wgpass"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

// Config is a relay's, as Connaio writes it on the server.
type Config struct {
	Password string   `json:"password"` // the tunnel's: the keys come from it (wgpass)
	Port     int      `json:"port"`     // the UDP port WireGuard takes Connaio's handshake on
	Peer     string   `json:"peer"`     // Connaio's tunnel address, e.g. 10.8.0.2
	Forwards []string `json:"forwards"` // where to listen on the server, e.g. 0.0.0.0:8080, or 127.0.0.1:1080 for the server only
}

// dialTimeout bounds the dial through the tunnel: Connaio may have gone since its last handshake.
const dialTimeout = 10 * time.Second

// Address is the relay's own tunnel address for Connaio's peer: the first of its /24, or the last
// when peer is the first.
func Address(peer netip.Addr) netip.Addr {
	b := peer.As4()
	b[3] = 1
	if b == peer.As4() {
		b[3] = 254
	}
	return netip.AddrFrom4(b)
}

// handshakeMax is how long Connaio's end may go without a handshake before it counts as offline: a
// live one handshakes every 2 minutes under its keepalives, and keys older than 3 are refused anyway.
const handshakeMax = 3 * time.Minute

// VersionPort is the port on the relay's tunnel address, reachable only through the tunnel, that
// answers Version: Connaio tells from it an outdated relay on the server.
const VersionPort = 1

// Version is the sha256 of the relay's own executable, hex: what Connaio compares with the relay it
// carries.
var Version = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
})

// Run serves cfg until ctx is done. It fails when cfg can't be served: a done ctx only checks that
// it can (connaio-relay -check).
func Run(ctx context.Context, cfg Config) error {
	keys, err := wgpass.Derive(cfg.Password)
	if err != nil {
		return err
	}
	peer, err := netip.ParseAddr(cfg.Peer)
	if err != nil || !peer.Is4() {
		return fmt.Errorf("peer %q is not an IPv4 address", cfg.Peer)
	}
	self := Address(peer)
	stack, err := mipstack.New(mipstack.Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(self, 32)},
		MTU:            1408, // the reverse tunnel's, Connaio's wireguard outbound default
		TCP: mipstack.TCPSocketDefaults{
			// BBR keeps its pace through loss, where CUBIC halves it: on a long lossy link to Connaio
			// (100ms, 1% loss) uploads went from 3 to 28 Mbit/s. Connaio's end sends with BBR too.
			CongestionControl: mipstack.CongestionControlBBR,
			// a peer gone without a word is noticed, its connections closed
			KeepAlive:       true,
			KeepAliveConfig: mipstack.KeepAliveConfig{Idle: 15 * time.Second, Interval: 15 * time.Second, Count: 4},
		},
	})
	if err != nil {
		return err
	}
	if err := stack.Start(); err != nil {
		return err
	}
	events := make(chan tun.Event, 1)
	events <- tun.EventUp
	dev := device.NewDevice(stackTun{stack, events}, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "wireguard: "), 0)
	defer dev.Close() // also closes the stack
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\npreshared_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(keys.Server.Bytes()), cfg.Port, hex.EncodeToString(keys.Local.PublicKey().Bytes()), hex.EncodeToString(keys.PSK), peer)); err != nil {
		return err
	}
	r := &relay{stack: stack}
	for _, f := range cfg.Forwards {
		ap, err := netip.ParseAddrPort(f)
		if err != nil {
			return fmt.Errorf("forward %q: %w", f, err)
		}
		ln, err := net.Listen("tcp", f)
		if err != nil {
			return err
		}
		defer ln.Close()
		go r.serve(ln, netip.AddrPortFrom(peer, ap.Port()))
		log.Printf("%s -> %s", f, netip.AddrPortFrom(peer, ap.Port()))
	}
	versions, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(self, VersionPort)) // not ctx: done under -check
	if err != nil {
		return err
	}
	defer versions.Close()
	go serveVersion(versions)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		conf, _ := dev.IpcGet()
		if up := time.Since(LastHandshake(conf)) < handshakeMax; up != r.up.Load() {
			r.up.Store(up)
			log.Print(map[bool]string{true: "Connaio connected", false: "Connaio offline: connections are refused until it is back"}[up])
		}
	}
}

// LastHandshake is the newest handshake with any peer in a WireGuard device's IpcGet, zero before
// the first.
func LastHandshake(conf string) time.Time {
	var last int64
	for _, line := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > last {
				last = sec
			}
		}
	}
	if last == 0 {
		return time.Time{}
	}
	return time.Unix(last, 0)
}

// serveVersion answers each connection with Version and closes it.
func serveVersion(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte(Version() + "\n"))
		c.Close()
	}
}

type relay struct {
	stack *mipstack.Stack
	up    atomic.Bool // Connaio's end handshook within handshakeMax
}

// serve hands each connection ln accepts to forward until ln closes; a failed accept (out of file
// descriptors) waits a little and goes on, as net/http's does.
func (r *relay) serve(ln net.Listener, target netip.AddrPort) {
	delay := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Printf("accept %s: %v", ln.Addr(), err)
			time.Sleep(delay)
			delay = min(2*delay, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		go r.forward(c, target)
	}
}

// forward carries c through the tunnel to target, both ways, until both are done. With Connaio
// offline it closes c at once instead of a dial that can only time out.
func (r *relay) forward(c net.Conn, target netip.AddrPort) {
	defer c.Close()
	if !r.up.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	t, err := r.stack.DialTCP(ctx, "tcp", netip.AddrPort{}, target)
	cancel()
	if err != nil {
		log.Printf("%s -> %s: %v", c.RemoteAddr(), target, err)
		return
	}
	defer t.Close()
	done := make(chan struct{})
	go func() { pipe(t, c); close(done) }()
	pipe(c, t)
	<-done
}

// pipe copies src to dst. At src's end dst's write side closes, so a half-closed connection goes on
// the other way; on an error both close, which ends the other way too.
func pipe(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		src.Close()
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
}

// stackTun is the IP stack as the WireGuard device's TUN.
type stackTun struct {
	*mipstack.Stack
	events chan tun.Event
}

func (d stackTun) File() *os.File           { return nil }
func (d stackTun) Events() <-chan tun.Event { return d.events }
func (d stackTun) Close() error             { close(d.events); return d.Stack.Close() }
