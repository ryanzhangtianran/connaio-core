package reverse

import (
	"bytes"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/net/deadline"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

const udpQueueSize = 128

// udpSession is one remote user's UDP session to target, routed by rules. frp's udp Forwarder
// writes the user's packets into it and reads the replies back, one session per user address.
type udpSession struct {
	tunnel    C.Tunnel
	target    socks5.Addr
	src       net.Addr
	additions []inbound.Addition
	readCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	deadline  deadline.PipeDeadline
}

func newUDPSession(tunnel C.Tunnel, target socks5.Addr, src net.Addr, additions ...inbound.Addition) *udpSession {
	return &udpSession{
		tunnel:    tunnel,
		target:    target,
		src:       src,
		additions: additions,
		readCh:    make(chan []byte, udpQueueSize),
		done:      make(chan struct{}),
		deadline:  deadline.MakePipeDeadline(),
	}
}

func (s *udpSession) Write(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	packet, metadata := inbound.NewPacket(s.target, &udpPacket{session: s, data: bytes.Clone(p)}, C.FRP, s.additions...)
	s.tunnel.HandleUDPPacket(packet, metadata)
	return len(p), nil
}

func (s *udpSession) Read(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	case <-s.deadline.Wait():
		return 0, os.ErrDeadlineExceeded
	case b := <-s.readCh:
		return copy(p, b), nil
	}
}

func (s *udpSession) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	return nil
}

// LocalAddr and RemoteAddr both report the user; frp's Forwarder uses neither.
func (s *udpSession) LocalAddr() net.Addr                { return s.src }
func (s *udpSession) RemoteAddr() net.Addr               { return s.src }
func (s *udpSession) SetDeadline(t time.Time) error      { return s.SetReadDeadline(t) }
func (s *udpSession) SetReadDeadline(t time.Time) error  { s.deadline.Set(t); return nil }
func (s *udpSession) SetWriteDeadline(_ time.Time) error { return nil }

type udpPacket struct {
	session *udpSession
	data    []byte
}

func (p *udpPacket) Data() []byte        { return p.data }
func (p *udpPacket) Drop()               {}
func (p *udpPacket) LocalAddr() net.Addr { return p.session.src }

// WriteBack queues a reply for the user, dropping it when the queue is full like a real socket.
func (p *udpPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	select {
	case <-p.session.done:
		return 0, net.ErrClosed
	case p.session.readCh <- bytes.Clone(b):
	default:
	}
	return len(b), nil
}
