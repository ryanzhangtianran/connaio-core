package easyconnect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

// A logged-in session: the packet tunnel, pumped against the kernel's IP stack.
//
// Three goroutines carry it. One reads the receiving stream into the stack,
// one writes the stack's packets to the sending stream, and one keeps the
// session alive. A broken stream is reopened, with up to five attempts in a
// row in each direction; after that the reason is recorded in Failed() and
// the goroutines end. Nothing here ends the process.

// MTU is the tunnel's.
const MTU = 1400

// Link is the packet side of an IP stack: Read takes packets the stack wants
// sent, Write hands it packets that arrived. The kernel's userspace stacks
// (mipstack, gVisor) have this shape.
type Link interface {
	Read(buffers [][]byte, sizes []int, offset int) (int, error)
	Write(buffers [][]byte, offset int) (int, error)
}

type Session struct {
	// The tunnel address the gateway handed this client.
	Address netip.Addr
	// What the gateway routes, and the resolvers it advertised.
	Routing Routing

	gw *Gateway
	// The connection that asked for the address. The gateway tears the tunnel down if it closes.
	control *tlsConn
	link    Link
	ctx     context.Context
	cancel  context.CancelFunc

	mu      sync.Mutex
	failure error
	closed  bool
	// The receiving and sending streams, to close them from another goroutine.
	streams [2]*tlsConn
	// Attempts to reopen in a row, per direction, and when the last one started.
	reopened [2]struct {
		count int
		last  time.Time
	}
}

// Open logs in (totpSecret is the base32 secret of a second factor, or empty) and opens the
// tunnel. Start then pumps it against a stack.
func Open(ctx context.Context, gw *Gateway, username, password, totpSecret string) (*Session, error) {
	if err := gw.Login(ctx, username, password, totpSecret); err != nil {
		return nil, err
	}
	if err := gw.RequestToken(ctx); err != nil {
		gw.Logout()
		return nil, err
	}
	started := time.Now()
	routing, err := gw.Resources(ctx)
	if err != nil { // a session with no routes would stay up matching nothing; failing here retries with the usual backoff
		gw.Logout()
		return nil, err
	}
	// The gateway refuses an address requested within a second of the token.
	if wait := time.Second - time.Since(started); wait > 0 {
		time.Sleep(wait)
	}
	control, err := gw.RequestAddress(ctx)
	if err != nil {
		gw.Logout()
		return nil, err
	}
	sender, err := gw.OpenTunnel(ctx, true)
	if err != nil {
		control.Close()
		gw.Logout()
		return nil, err
	}
	receiver, err := gw.OpenTunnel(ctx, false)
	if err != nil {
		sender.Close()
		control.Close()
		gw.Logout()
		return nil, err
	}
	s := &Session{
		Address: netip.AddrFrom4(gw.address),
		Routing: routing,
		gw:      gw,
		control: control,
		streams: [2]*tlsConn{receiver, sender},
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// Start carries packets between the tunnel and link until Close, or the
// tunnel fails for good.
func (s *Session) Start(link Link) {
	s.link = link
	go s.guard(s.receive)
	go s.guard(s.send)
	go s.guard(s.keepalive)
}

// Failed is why the tunnel stopped carrying traffic, or nil while it still does.
func (s *Session) Failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

func (s *Session) Close() {
	s.mu.Lock()
	s.closed = true
	streams := s.streams
	s.streams = [2]*tlsConn{}
	s.mu.Unlock()
	s.cancel()
	for _, c := range streams {
		if c != nil {
			c.Close()
		}
	}
	s.control.Close()
	go s.gw.Logout() // frees the account for the next login; best effort, and callers hold the outbound's lock
}

// guard runs a goroutine's body, recording a panic as the failure rather than
// taking the kernel down with it.
func (s *Session) guard(f func()) {
	defer func() {
		if r := recover(); r != nil {
			s.fail(fmt.Errorf("internal error in the EasyConnect engine: %v", r))
		}
	}()
	f()
}

// receive reads packets from the gateway until the session closes.
func (s *Session) receive() {
	stream := s.stream(0)
	packets := make([][]byte, 0, 8)
	for {
		record, err := stream.Read()
		if err != nil {
			if stream = s.reopen(false, err); stream == nil {
				return
			}
			continue
		}
		// Normally a record holds one packet, but split it in case it holds several. The
		// stack copies what it keeps before Write returns, so the record buffer can be reused.
		packets = packets[:0]
		for offset := 0; offset+20 <= len(record); {
			length := int(binary.BigEndian.Uint16(record[offset+2:]))
			if length < 20 || offset+length > len(record) {
				break
			}
			packets = append(packets, record[offset:offset+length])
			offset += length
		}
		if len(packets) > 0 {
			if _, err := s.link.Write(packets, 0); err != nil {
				s.fail(err) // a no-op once closed, which is the usual reason
				return
			}
		}
	}
}

// send writes what the stack has queued, a batch per write, still one record
// per packet.
func (s *Session) send() {
	stream := s.stream(1)
	const batch = 64
	buffers := make([][]byte, batch)
	for i := range buffers {
		buffers[i] = make([]byte, 4096)
	}
	sizes := make([]int, batch)
	packets := make([][]byte, batch)
	for {
		n, err := s.link.Read(buffers, sizes, 0)
		if err != nil && !errors.Is(err, io.ErrShortBuffer) { // a packet past the MTU is dropped, not the tunnel; the n before it were read
			s.fail(err)
			return
		}
		packets = packets[:n]
		for i := range packets {
			packets[i] = buffers[i][:sizes[i]]
		}
		_ = stream.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := stream.WriteEach(packets); err != nil {
			if stream = s.reopen(true, err); stream == nil {
				return
			}
			_ = stream.SetWriteDeadline(time.Now().Add(15 * time.Second))
			_ = stream.WriteEach(packets)
		}
	}
}

func (s *Session) keepalive() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if !s.gw.UpdateSession(s.ctx) {
				return
			}
		}
	}
}

// reopen replaces a broken stream, making up to five attempts in a row in each
// direction. A failed attempt waits before the next, half a second and then
// twice as long each time, so a network change has a few seconds to settle. A
// stream that then lasts a minute starts the count again, so a long session
// survives any number of network changes.
func (s *Session) reopen(sending bool, err error) *tlsConn {
	i := 0
	if sending {
		i = 1
	}
	pause := 500 * time.Millisecond
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil
		}
		r := &s.reopened[i]
		if time.Since(r.last) > time.Minute {
			r.count = 0
		}
		r.count++
		r.last = time.Now()
		count := r.count
		s.mu.Unlock()
		if count > 5 {
			s.fail(err)
			return nil
		}
		fresh, openErr := s.gw.OpenTunnel(s.ctx, sending)
		if openErr == nil {
			return s.install(i, fresh)
		}
		err = openErr
		if count < 5 {
			select {
			case <-s.ctx.Done():
				return nil
			case <-time.After(pause):
			}
			pause *= 2
		}
	}
}

// install puts a fresh stream in place of the broken one, which is closed.
func (s *Session) install(i int, fresh *tlsConn) *tlsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		fresh.Close()
		return nil
	}
	if broken := s.streams[i]; broken != nil {
		broken.Close()
	}
	s.streams[i] = fresh
	return fresh
}

// stream is the current stream of one direction.
func (s *Session) stream(i int) *tlsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[i]
}

// fail records why the tunnel stopped and ends the keepalive with it.
func (s *Session) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && s.failure == nil {
		s.failure = err
		s.cancel()
	}
}
