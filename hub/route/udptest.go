package route

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// resolveUDP resolves host with the core's resolver (Go's own is disabled in the core).
func resolveUDP(ctx context.Context, host string, port uint16) (*net.UDPAddr, error) {
	ip, err := resolver.ResolveIPv4(ctx, host)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)), nil
}

// udpPacketConn opens a UDP association through proxy to host:port.
func udpPacketConn(ctx context.Context, proxy C.Proxy, host string, port uint16) (C.PacketConn, *net.UDPAddr, error) {
	addr, err := resolveUDP(ctx, host, port)
	if err != nil {
		return nil, nil, err
	}
	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: addr.AddrPort().Addr(), DstPort: port})
	return pc, addr, err
}

// exchange sends req and waits for one reply, returning it and the round trip.
func exchange(pc C.PacketConn, to net.Addr, req []byte) ([]byte, time.Duration, error) {
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := pc.WriteTo(req, to); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, 0, err
	}
	return buf[:n], time.Since(start), nil
}

// getProxyUDP checks UDP relay through the proxy: a DNS query to 1.1.1.1, timed.
func getProxyUDP(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	pc, to, err := udpPacketConn(ctx, proxy, "1.1.1.1", 53)
	if err != nil {
		fail(w, r, http.StatusBadGateway, err.Error())
		return
	}
	defer pc.Close()
	// a query for example.com A, id 0x1234, recursion desired
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	resp, rtt, err := exchange(pc, to, q)
	if err == nil && (len(resp) < 2 || resp[0] != 0x12 || resp[1] != 0x34) {
		err = errors.New("unexpected DNS reply")
	}
	if err != nil {
		fail(w, r, http.StatusGatewayTimeout, err.Error())
		return
	}
	render.JSON(w, r, render.M{"server": to.String(), "delay": rtt.Milliseconds()})
}

var stunServers = []struct {
	host string
	port uint16
}{{"stun.l.google.com", 19302}, {"stun.cloudflare.com", 3478}}

// getProxyNAT asks two STUN servers, over one UDP association through the proxy, which address
// they see: the same mapping for both is endpoint-independent (full, restricted or port-restricted
// cone), different ones mean a symmetric NAT.
// ponytail: mapping only; filtering behaviour (RFC 5780's CHANGE-REQUEST tests) is not probed.
func getProxyNAT(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	pc, _, err := udpPacketConn(ctx, proxy, stunServers[0].host, stunServers[0].port)
	if err != nil {
		fail(w, r, http.StatusBadGateway, err.Error())
		return
	}
	defer pc.Close()
	var mapped []string
	for _, s := range stunServers {
		if to, err := resolveUDP(ctx, s.host, s.port); err == nil {
			if m, err := stunBinding(pc, to); err == nil {
				mapped = append(mapped, m)
			}
		}
	}
	nat := "无法判断"
	switch {
	case len(mapped) == 0:
		fail(w, r, http.StatusGatewayTimeout, "STUN 服务器没有响应，节点可能不支持 UDP")
		return
	case len(mapped) == 2 && mapped[0] == mapped[1]:
		nat = "端点无关映射（锥形 NAT），适合游戏和语音通话"
	case len(mapped) == 2:
		nat = "端点相关映射（对称型 NAT），P2P 连接可能受限"
	}
	render.JSON(w, r, render.M{"mapped": mapped, "nat": nat})
}

func fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	render.Status(r, status)
	render.JSON(w, r, newError(msg))
}

// stunBinding sends an RFC 5389 binding request and returns the XOR-MAPPED-ADDRESS it gets back.
func stunBinding(pc C.PacketConn, to net.Addr) (string, error) {
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)     // binding request
	binary.BigEndian.PutUint32(req[4:], 0x2112A442) // magic cookie
	_, _ = rand.Read(req[8:20])
	resp, _, err := exchange(pc, to, req)
	if err != nil {
		return "", err
	}
	if len(resp) < 20 || string(resp[8:20]) != string(req[8:20]) {
		return "", errors.New("unexpected STUN reply")
	}
	for b := resp[20:]; len(b) >= 4; {
		typ, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+n {
			break
		}
		v := b[4 : 4+n]
		if typ == 0x0020 && n >= 8 && v[1] == 1 { // XOR-MAPPED-ADDRESS, IPv4
			port := binary.BigEndian.Uint16(v[2:]) ^ 0x2112
			ip := make(net.IP, 4)
			for i := range ip {
				ip[i] = v[4+i] ^ req[4+i]
			}
			return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
		}
		b = b[min(len(b), 4+(n+3)&^3):]
	}
	return "", errors.New("no mapped address")
}
