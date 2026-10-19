package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/easyconnect"

	E "github.com/metacubex/sing/common/exceptions"
)

// EasyConnect is a Sangfor EasyConnect (SSL VPN) gateway as an outbound. The
// login and the packet tunnel are in transport/easyconnect; the packets go
// through the same userspace IP stack as WireGuard. No TUN device, no root.
//
// The tunnel is opened in the background once the config is applied
// (ApplyEasyConnects) and on demand by a dial, and reopened after it fails.
type EasyConnect struct {
	*Base
	option EasyConnectOption

	// mu guards the fields. A login runs without it, so rule matching and status reads never
	// wait on the gateway; connecting and done serialise logins instead.
	mu         sync.Mutex
	closed     bool
	session    *easyconnect.Session
	stack      ipStack
	resolver   resolver.Resolver
	connecting bool
	// successor is the outbound a reload replaced this one with while its login was running; the
	// login's result goes to it, so a reload during startup doesn't log in twice (the gateway allows
	// one session per account) nor abandon a session.
	successor *EasyConnect
	done      chan struct{} // closed when the login in progress ends
	lastError error
	lastTry   time.Time
	// kicks are when the gateway ended the session lately; kicked says it did kickLimit times
	// within kickWindow, so the account is likely signed in elsewhere too and logging in again
	// would only take turns with it: no more logins until Reconnect.
	kicks  []time.Time
	kicked bool
}

const (
	kickLimit  = 3
	kickWindow = 10 * time.Minute
)

// errKicked stands for kicked in lastError and the status.
var errKicked = E.New("the gateway keeps ending the session: the account is probably signed in elsewhere; reconnect by hand")

// noteLost records a lost tunnel; called with mu held.
func (e *EasyConnect) noteLost(err error) {
	if !errors.Is(err, easyconnect.ErrSessionEnded) {
		return
	}
	now := time.Now()
	e.kicks = append(slices.DeleteFunc(e.kicks, func(t time.Time) bool { return now.Sub(t) > kickWindow }), now)
	if len(e.kicks) >= kickLimit {
		e.kicked, e.lastError = true, errKicked
		log.Warnln("[EasyConnect](%s) the gateway ended the session %d times in %s: the account is probably signed in elsewhere; not logging in again until reconnected", e.Name(), len(e.kicks), kickWindow)
	}
}

// Reconnect drops the tunnel, forgets a pause for being signed in elsewhere, and logs in again.
func (e *EasyConnect) Reconnect() {
	e.mu.Lock()
	e.kicked, e.kicks, e.lastError = false, nil, nil
	if !e.connecting {
		e.teardown()
	}
	e.mu.Unlock()
	e.kick()
}

// ReconnectEasyConnect reconnects the named outbound (EasyConnect.Reconnect).
func ReconnectEasyConnect(name string) error {
	r, ok := easyconnect.Routers()[name]
	if !ok {
		return fmt.Errorf("no EasyConnect outbound named %s", name)
	}
	r.(*EasyConnect).Reconnect()
	return nil
}

type EasyConnectOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	UserName   string `proxy:"username"`
	Password   string `proxy:"password"`
	TOTPSecret string `proxy:"totp-secret,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	// SkipRoutes are gateway routes (Range.Key, or a name) the EASYCONNECT rule leaves to the
	// rules after it; not part of key(), so changing them keeps the session.
	SkipRoutes []string `proxy:"skip-routes,omitempty"`
}

// EasyConnectStatus is what the API reports for one outbound.
type EasyConnectStatus struct {
	Name    string               `json:"name"`
	State   string               `json:"state"` // up, connecting, down
	Error   string               `json:"error,omitempty"`
	Kicked  bool                 `json:"kicked,omitempty"` // paused: the account is probably signed in elsewhere
	Address string               `json:"address,omitempty"`
	Routing *easyconnect.Routing `json:"routing,omitempty"`
}

// ApplyEasyConnects runs once a config is applied: its outbounds become the live ones (the
// easyconnect registry, which the EASYCONNECT rule and the API read), each taking over the tunnel
// of the one it replaces when the settings match, and outbounds no longer in the config are
// closed. Registering at apply time rather than at parse time means a config the core then rejects
// changes nothing, and a dropped outbound is closed now, not at GC. Only the config's own proxies
// are registered: an EasyConnect node inside a proxy provider still works as a plain outbound (it
// logs in when dialled) but can't be named by an EASYCONNECT rule.
func ApplyEasyConnects(proxies map[string]C.Proxy) {
	old := easyconnect.Routers()
	next := map[string]easyconnect.Router{}
	for name, p := range proxies {
		e, ok := unwrapEasyConnect(p)
		if !ok {
			continue
		}
		if prev, _ := old[name].(*EasyConnect); prev != nil && prev != e {
			prev.handOver(e)
		}
		next[name] = e
	}
	easyconnect.SetRouters(next)
	for name, prev := range old {
		if next[name] != prev {
			_ = prev.(*EasyConnect).Close()
		}
	}
	for _, e := range next {
		e.(*EasyConnect).kick()
	}
}

// unwrapEasyConnect finds the outbound behind a proxy's wrappers.
func unwrapEasyConnect(p C.Proxy) (*EasyConnect, bool) {
	var a any = p.Adapter()
	for {
		switch v := a.(type) {
		case *EasyConnect:
			return v, true
		case interface{ Inner() ProxyAdapter }:
			a = v.Inner()
		default:
			return nil, false
		}
	}
}

func EasyConnectStatuses() []EasyConnectStatus {
	var statuses []EasyConnectStatus
	for _, e := range easyconnect.Routers() {
		statuses = append(statuses, e.(*EasyConnect).Status())
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	return statuses
}

// key is the settings a tunnel depends on; two outbounds with the same key can share one.
func (o EasyConnectOption) key() string {
	return fmt.Sprintf("%s|%d|%s|%s|%s|%s", o.Server, o.Port, o.UserName, o.Password, o.TOTPSecret, o.Interface)
}

func NewEasyConnect(option EasyConnectOption) (*EasyConnect, error) {
	if option.Server == "" || option.UserName == "" {
		return nil, E.New("easyconnect needs server and username")
	}
	if option.Port == 0 {
		option.Port = 443
	}
	outbound := &EasyConnect{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.EasyConnect,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// handOver gives a replacement outbound this one's tunnel when the settings
// match, else closes it: the gateway allows one session per login, so the
// outdated outbound must not keep one. Either way this one is finished; a
// late dial on it fails instead of logging in again.
func (e *EasyConnect) handOver(to *EasyConnect) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	same := e.option.key() == to.option.key()
	if same { // a reload keeps the count, and a pause for being signed in elsewhere
		to.mu.Lock()
		to.kicks, to.kicked = e.kicks, e.kicked
		if e.kicked {
			to.lastError, to.lastTry = e.lastError, e.lastTry
		}
		to.mu.Unlock()
	}
	switch {
	case same && e.session != nil && e.session.Failed() == nil:
		to.mu.Lock()
		to.session, to.stack = e.session, e.stack
		to.resolver = to.newResolver(e.session.Routing.DNS)
		to.mu.Unlock()
		e.session, e.stack, e.resolver = nil, nil, nil
		return
	case same && e.connecting:
		to.mu.Lock()
		to.connecting, to.done = true, e.done // dials on the successor wait for this login
		to.mu.Unlock()
		e.successor = to
		return
	}
	e.teardown()
}

var errClosed = E.New("closed")

// adopt gives a login's result to the successor a reload installed meanwhile (or its successor).
func (e *EasyConnect) adopt(session *easyconnect.Session, stack ipStack, err error) {
	s := e.successor
	for {
		s.mu.Lock()
		if s.closed && s.successor != nil {
			next := s.successor
			s.mu.Unlock()
			s = next
			continue
		}
		s.connecting = false
		s.lastTry, s.lastError = time.Now(), err
		if err == nil && !s.closed {
			s.session, s.stack = session, stack
			s.resolver = s.newResolver(session.Routing.DNS)
		} else if err == nil {
			session.Close()
			_ = stack.Close()
		}
		s.mu.Unlock()
		return
	}
}

// kick starts a login in the background unless one is running, the tunnel is
// up, or an attempt has to wait.
func (e *EasyConnect) kick() {
	e.mu.Lock()
	skip := e.closed || e.connecting || (e.session != nil && e.session.Failed() == nil) || e.waiting()
	e.mu.Unlock()
	if skip {
		return
	}
	go func() {
		if _, _, err := e.connect(context.Background()); err != nil && !errors.Is(err, errClosed) {
			log.Warnln("[EasyConnect](%s) %s", e.Name(), err)
		}
	}()
}

// waiting says the last attempt failed, or the tunnel was just lost, so another attempt has to
// wait: thirty seconds, or ten minutes when the gateway refused the login outright (a wrong
// password won't fix itself; a rate limit will). Called with mu held.
func (e *EasyConnect) waiting() bool {
	if e.kicked {
		return true
	}
	if e.lastError == nil {
		return false
	}
	var refused *easyconnect.RefusedError
	if errors.As(e.lastError, &refused) {
		return time.Since(e.lastTry) < 10*time.Minute
	}
	return time.Since(e.lastTry) < 30*time.Second
}

// connect logs in on first use, and again if the tunnel has since failed, and returns the stack
// and resolver to dial with: a snapshot, since another goroutine may replace them next. A dial
// arriving while a login runs waits for it, or for its own context.
func (e *EasyConnect) connect(ctx context.Context) (ipStack, resolver.Resolver, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, nil, errClosed
	}
	if e.session != nil {
		if err := e.session.Failed(); err == nil {
			stack, r := e.stack, e.resolver
			e.mu.Unlock()
			return stack, r, nil
		} else {
			log.Warnln("[EasyConnect](%s) tunnel lost: %s", e.Name(), err)
			e.teardown()
			e.lastTry, e.lastError = time.Now(), fmt.Errorf("tunnel lost: %w", err)
			e.noteLost(err)
		}
	}
	if e.connecting {
		done := e.done
		e.mu.Unlock()
		select {
		case <-done:
			return e.connect(ctx) // the state the login left behind decides
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if e.waiting() {
		err := e.lastError
		e.mu.Unlock()
		return nil, nil, err
	}
	e.connecting, e.done = true, make(chan struct{})
	e.mu.Unlock()

	session, stack, err := e.login()

	e.mu.Lock()
	defer e.mu.Unlock()
	e.connecting = false
	defer close(e.done) // after the successor has the result, so a waiting dial sees it
	e.lastTry, e.lastError = time.Now(), err
	if e.closed && e.successor != nil {
		e.adopt(session, stack, err)
		return nil, nil, errClosed
	}
	if err != nil {
		return nil, nil, err
	}
	if e.closed {
		session.Close()
		_ = stack.Close()
		return nil, nil, errClosed
	}
	e.session, e.stack = session, stack
	e.resolver = e.newResolver(session.Routing.DNS)
	return stack, e.resolver, nil
}

// login opens the tunnel and the stack on it; it touches nothing on e but its settings.
func (e *EasyConnect) login() (*easyconnect.Session, ipStack, error) {
	// A login is several round trips and a one-second pause, longer than a
	// connection's own context allows.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	gw := easyconnect.NewGateway(e.option.Server, e.option.Port, func(ctx context.Context) (net.Conn, error) {
		return e.dialer.DialContext(ctx, "tcp", e.addr)
	})
	session, err := easyconnect.Open(ctx, gw, e.option.UserName, e.option.Password, e.option.TOTPSecret)
	if err != nil {
		return nil, nil, E.Cause(err, "login")
	}
	stack, err := newIPStack(IPStackOption{Mode: ipStackAuto}, []netip.Prefix{netip.PrefixFrom(session.Address, 32)}, easyconnect.MTU)
	if err == nil {
		err = stack.Start()
	}
	if err != nil {
		session.Close()
		return nil, nil, E.Cause(err, "create stack")
	}
	session.Start(stack)
	log.Infoln("[EasyConnect](%s) tunnel up: address %s, %d ranges, %d domains, DNS %v", e.Name(), session.Address, len(session.Routing.IP), len(session.Routing.Domains), session.Routing.DNS)
	return session, stack, nil
}

// newResolver resolves through the tunnel with the servers the gateway advertised.
func (e *EasyConnect) newResolver(servers []string) resolver.Resolver {
	if len(servers) == 0 {
		return nil
	}
	nss, err := dns.ParseNameServer(servers)
	if err != nil {
		log.Warnln("[EasyConnect](%s) ignoring DNS %v: %s", e.Name(), servers, err)
		return nil
	}
	for i := range nss {
		nss[i].ProxyAdapter = e
	}
	return dns.NewResolver(dns.Config{Main: nss})
}

func (e *EasyConnect) teardown() {
	if e.session != nil {
		e.session.Close()
		e.session = nil
	}
	if e.stack != nil {
		_ = e.stack.Close()
		e.stack = nil
	}
	e.resolver = nil
}

// Routing is what the gateway routes less SkipRoutes, or nil while the tunnel
// is down; a down tunnel is started in the background.
func (e *EasyConnect) Routing() *easyconnect.Routing {
	e.mu.Lock()
	up := e.session != nil && e.session.Failed() == nil
	var routing easyconnect.Routing
	if up {
		routing = e.session.Routing.Without(e.option.SkipRoutes)
	}
	e.mu.Unlock()
	if !up {
		e.kick()
		return nil
	}
	return &routing
}

func (e *EasyConnect) Status() EasyConnectStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := EasyConnectStatus{Name: e.Name(), State: "down", Kicked: e.kicked}
	switch {
	case e.session != nil && e.session.Failed() == nil:
		s.State, s.Address = "up", e.session.Address.String()
		routing := e.session.Routing
		s.Routing = &routing
	case e.connecting:
		s.State = "connecting"
	}
	if err := e.lastError; err != nil && s.State != "up" {
		s.Error = err.Error()
	}
	if e.session != nil {
		if err := e.session.Failed(); err != nil {
			s.Error = err.Error()
		}
	}
	return s
}

// DialContext implements C.ProxyAdapter
func (e *EasyConnect) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	stack, r, err := e.connect(ctx)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	if !metadata.Resolved() || r != nil {
		if r == nil {
			r = resolver.DefaultResolver
		}
		options := append(e.DialOptions(), dialer.WithResolver(r), dialer.WithNetDialer(ipStackNetDialer{stack: stack}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = stack.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, E.New("conn is nil")
	}
	return NewConn(conn, e), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (e *EasyConnect) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	stack, r, err := e.connect(ctx)
	if err != nil {
		return nil, err
	}
	if err = e.resolveUDP(ctx, metadata, r); err != nil {
		return nil, err
	}
	pc, err := stack.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return NewPacketConn(pc, e), nil
}

// ResolveUDP implements C.ProxyAdapter
func (e *EasyConnect) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	e.mu.Lock()
	r := e.resolver
	e.mu.Unlock()
	return e.resolveUDP(ctx, metadata, r)
}

func (e *EasyConnect) resolveUDP(ctx context.Context, metadata *C.Metadata, r resolver.Resolver) error {
	if (!metadata.Resolved() || r != nil) && metadata.Host != "" {
		if r == nil {
			r = resolver.DefaultResolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, e.prefer, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter
func (e *EasyConnect) ProxyInfo() C.ProxyInfo {
	info := e.Base.ProxyInfo()
	info.DialerProxy = e.option.DialerProxy
	return info
}

// IsL3Protocol implements C.ProxyAdapter
func (e *EasyConnect) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

// Close implements C.ProxyAdapter. The registry is kept by ApplyEasyConnects alone; a wrapper's
// finalizer closing an outdated outbound never touches it.
func (e *EasyConnect) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.teardown()
	return nil
}
