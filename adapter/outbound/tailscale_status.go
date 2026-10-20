package outbound

import (
	"context"
	"sort"

	C "github.com/metacubex/mihomo/constant"
)

// TailscaleStatus is a Tailscale outbound's login state for a client: NeedsLogin with the address
// to log in at, Running once in the tailnet, with its addresses there.
type TailscaleStatus struct {
	Name    string   `json:"name"`
	State   string   `json:"state"` // ipn.State: NoState, NeedsLogin, NeedsMachineAuth, Starting, Running, Stopped; "" with Error
	AuthURL string   `json:"authURL,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	// Routes are the subnets the tailnet's other nodes advertise (and the admin approved), each with
	// the node that serves it; reaching one needs accept-routes
	Routes []TailscaleRoute `json:"routes,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// TailscaleRoute is one advertised subnet and the node behind it.
type TailscaleRoute struct {
	Prefix string `json:"prefix"`
	Node   string `json:"node"`
	Online bool   `json:"online"`
}

// TailscaleStatuses reads every Tailscale outbound among proxies, by name, starting those nothing
// has used yet: one starts on its first connection, and without a start there is no login link.
func TailscaleStatuses(ctx context.Context, proxies map[string]C.Proxy) []TailscaleStatus {
	var out []TailscaleStatus
	for _, p := range proxies {
		a := p.Adapter()
		if w, ok := a.(*autoCloseProxyAdapter); ok { // the parser wraps every outbound so
			a = w.ProxyAdapter
		}
		if t, ok := a.(*Tailscale); ok {
			out = append(out, t.Status(ctx))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
