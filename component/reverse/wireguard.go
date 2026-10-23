package reverse

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/relay"
	"github.com/metacubex/mihomo/component/wgpass"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// wgHandshakeMax is how long a session may go without a handshake before it counts as dead: a live
// peer handshakes every 2 minutes under the keepalives, and keys older than 3 are refused anyway.
const wgHandshakeMax = 3 * time.Minute

// wgKeepAlive is the persistent keepalive when none is set: what brings the session up without
// traffic, and keeps the server able to reach this end behind NAT.
const wgKeepAlive = 25

var errNoHandshake = errors.New("no handshake with the server")

// relayAsk is how often a running tunnel asks connaio-relay for its version. The ask is data, so
// WireGuard handshakes again when no answer comes: a relay restarted on the server, which knows
// nothing of this end until then, takes visitors again within this and 15s.
const relayAsk = 30 * time.Second

// relayVersion asks connaio-relay at addr, through the tunnel, for its version; "" when nothing
// answers (a relay from before it answered, or a server of the user's own).
func relayVersion(ctx context.Context, out *outbound.WireGuard, addr netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: addr, DstPort: relay.VersionPort})
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	line, _ := bufio.NewReader(io.LimitReader(c, 128)).ReadString('\n')
	return strings.TrimSpace(line)
}

// wgOption reuses the wireguard outbound options (keys, peer, ip, dialer-proxy) plus the forwards,
// each taking on this end's tunnel address the port its remote is on the server. A `password` in
// place of the keys gives them (wgpass), as connaio-relay on the server derives its own.
type wgOption struct {
	outbound.WireGuardOption
	Forwards []forward `proxy:"forwards"`
}

func parseWireGuard(t *Tunnel, mapping map[string]any, tunnel C.Tunnel) error {
	if password, _ := mapping["password"].(string); password != "" {
		k, err := wgpass.Derive(password)
		if err != nil {
			return err
		}
		b64 := base64.StdEncoding.EncodeToString
		mapping = maps.Clone(mapping)
		mapping["private-key"], mapping["public-key"], mapping["pre-shared-key"] = b64(k.Local.Bytes()), b64(k.Server.PublicKey().Bytes()), b64(k.PSK)
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := wgOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return err
	}
	if err := parseForwards(opt.Forwards); err != nil {
		return err
	}
	keys := map[string]string{"private-key": opt.PrivateKey}
	if len(opt.Peers) == 0 {
		keys["public-key"] = opt.PublicKey
	}
	for field, key := range keys { // the outbound takes an empty one, and the tunnel would just never come up
		if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 32 {
			return fmt.Errorf("invalid %s", field)
		}
	}
	opt.TunnelForAPI = tunnel
	if opt.PersistentKeepalive == 0 {
		opt.PersistentKeepalive = wgKeepAlive
	}
	if opt.IPStack.CongestionController == "" {
		// BBR keeps its pace through loss, where CUBIC halves it: on a long lossy link to the server
		// (100ms, 1% loss) downloads went from 2 to 69 Mbit/s. connaio-relay sends with BBR too.
		opt.IPStack.CongestionController = "bbr"
	}
	if opt.MTU == 0 {
		opt.MTU = relay.MTU // see there: the outbound's 1408 outgrows many servers' paths, a dialer-proxy's headers on top even more
	}
	var relayAt netip.Addr // connaio-relay's tunnel address, asked for its version: a password tunnel's server is one
	if _, ok := mapping["password"].(string); ok {
		if ip, err := netip.ParsePrefix(opt.Ip); err == nil {
			relayAt = relay.Address(ip.Addr())
		} else if ip, err := netip.ParseAddr(opt.Ip); err == nil && ip.Is4() {
			relayAt = relay.Address(ip)
		}
	}
	check, err := outbound.NewWireGuard(opt.WireGuardOption) // keys and addresses checked now, not at the first try
	if err != nil {
		return err
	}
	check.Close()
	t.DialerProxy = opt.DialerProxy
	t.run = func(ctx context.Context) {
		t.retry(ctx, func(ctx context.Context, up func()) error { return serveWireGuard(ctx, t, opt, tunnel, relayAt, up) })
	}
	t.detail = func(s *Status) {
		for _, f := range opt.Forwards {
			s.Forwards = append(s.Forwards, ForwardStatus{Remote: f.Remote, Local: f.Local})
		}
	}
	return nil
}

// serveWireGuard holds one WireGuard device with all forwards until ctx is done or the server has
// gone wgHandshakeMax without a handshake; each try builds the device anew, resolving the server
// again. While up it asks connaio-relay at relayAt (when valid) for its version now and then.
func serveWireGuard(ctx context.Context, t *Tunnel, opt wgOption, tunnel C.Tunnel, relayAt netip.Addr, up func()) error {
	name := t.Name
	out, err := outbound.NewWireGuard(opt.WireGuardOption)
	if err != nil {
		return err
	}
	defer out.Close() // also closes every listener below
	for _, f := range opt.Forwards {
		ln, err := out.ListenTCP(ctx, netip.AddrPortFrom(netip.IPv4Unspecified(), netip.MustParseAddrPort(f.Remote).Port()))
		if err != nil {
			return fmt.Errorf("listen %s: %w", f.Remote, err)
		}
		defer ln.Close()
		go acceptLoop(tunnel, name, ln, f.target)
		log.Infoln("[ReverseTunnel] %s: %s -> local %s", name, f.Remote, f.Local)
	}

	start, running, asked := time.Now(), false, time.Time{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		last := out.LastHandshake()
		if time.Since(last) < wgHandshakeMax {
			if !running {
				running = true
				up()
			}
			// again and again: a relay reinstalled on the server answers with its new version
			if relayAt.IsValid() && time.Since(asked) > relayAsk {
				asked = time.Now()
				go func() { t.setRelay(relayVersion(ctx, out, relayAt)) }()
			}
			continue
		}
		if last.Before(start) {
			last = start
		}
		if time.Since(last) > wgHandshakeMax {
			return fmt.Errorf("%w in %s", errNoHandshake, wgHandshakeMax)
		}
	}
}
