// Package reverse runs reverse tunnels (ssh -R) that expose local services through a remote server.
package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// retryInterval is the wait after a failure, doubling up to retryMax while they go on.
const (
	retryInterval = 10 * time.Second
	retryMax      = time.Minute
)

const (
	StateConnecting = "connecting"
	StateRunning    = "running"
	StateRetrying   = "retrying"
	StateStopped    = "stopped" // disabled in the config: listed, not run
)

type Tunnel struct {
	Name        string
	Type        string
	DialerProxy string
	Disabled    bool   // `disabled: true`: kept in the config, stopped
	hash        string // raw config fingerprint, so a reload only restarts tunnels that changed
	run         func(ctx context.Context)
	detail      func(s *Status) // fills Forwards, may refine State

	mu    sync.Mutex
	state Status // State/Error/Since, set by retry
}

// Status is a tunnel's live state, served by GET /reverse-tunnels.
type Status struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	State    string          `json:"state"`
	Error    string          `json:"error,omitempty"`
	Since    time.Time       `json:"since"`
	Forwards []ForwardStatus `json:"forwards"`
}

type ForwardStatus struct {
	Remote string `json:"remote"`
	Local  string `json:"local"`
}

// Parse builds a tunnel from one `reverse-tunnels` entry. tunnel resolves dialer-proxy names
// and routes incoming connections by rules.
func Parse(mapping map[string]any, tunnel C.Tunnel) (*Tunnel, error) {
	name, _ := mapping["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}
	raw, err := json.Marshal(mapping)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	disabled, _ := mapping["disabled"].(bool)
	t := &Tunnel{Name: name, Disabled: disabled, hash: string(raw)}
	switch t.Type, _ = mapping["type"].(string); t.Type {
	case "ssh":
		err = parseSSH(t, mapping, tunnel)
	default:
		err = fmt.Errorf("unsupported type %q", t.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return t, nil
}

func (t *Tunnel) setState(state string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.State != state {
		t.state.Since = time.Now()
	}
	t.state.State, t.state.Error = state, ""
	if err != nil {
		t.state.Error = err.Error()
	}
}

func (t *Tunnel) Status() Status {
	t.mu.Lock()
	s := t.state
	t.mu.Unlock()
	s.Name, s.Type = t.Name, t.Type
	t.detail(&s)
	return s
}

// retry calls serve until ctx is done, waiting retryInterval after a failure, longer after each in
// a row, retryInterval again once a serve came up.
// serve calls up once its session is established.
func (t *Tunnel) retry(ctx context.Context, serve func(ctx context.Context, up func()) error) {
	delay := retryInterval
	for {
		t.setState(StateConnecting, nil)
		err := serve(ctx, func() { delay = retryInterval; t.setState(StateRunning, nil) })
		if ctx.Err() != nil {
			return
		}
		t.setState(StateRetrying, err)
		log.Warnln("[ReverseTunnel] %s: %v, retry in %s", t.Name, err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, retryMax)
	}
}

var (
	mu      sync.Mutex
	active  = map[string]*running{}
	stopped []*Tunnel // the disabled ones, for Statuses
)

type running struct {
	tunnel *Tunnel
	cancel context.CancelFunc
}

// Patch starts new or changed tunnels and stops removed or changed ones.
func Patch(tunnels []*Tunnel) {
	mu.Lock()
	defer mu.Unlock()
	next := make(map[string]*Tunnel, len(tunnels))
	stopped = nil
	for _, t := range tunnels {
		if t.Disabled {
			t.setState(StateStopped, nil)
			stopped = append(stopped, t)
			continue
		}
		next[t.Name] = t
	}
	for name, r := range active {
		if t, ok := next[name]; !ok || t.hash != r.tunnel.hash {
			log.Infoln("[ReverseTunnel] %s stopped", name)
			r.cancel()
			delete(active, name)
		}
	}
	for name, t := range next {
		if _, ok := active[name]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		active[name] = &running{tunnel: t, cancel: cancel}
		log.Infoln("[ReverseTunnel] %s starting", name)
		go t.run(ctx)
	}
}

// Statuses reports every tunnel, running or stopped, sorted by name.
func Statuses() []Status {
	mu.Lock()
	tunnels := make([]*Tunnel, 0, len(active)+len(stopped))
	for _, r := range active {
		tunnels = append(tunnels, r.tunnel)
	}
	tunnels = append(tunnels, stopped...)
	mu.Unlock()
	slices.SortFunc(tunnels, func(a, b *Tunnel) int { return strings.Compare(a.Name, b.Name) })
	statuses := make([]Status, len(tunnels))
	for i, t := range tunnels {
		statuses[i] = t.Status()
	}
	return statuses
}
