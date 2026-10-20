package common

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/easyconnect"
)

// EasyConnect matches what the named EasyConnect outbound's gateway routes:
// the names and address ranges it advertised at login. Nothing matches until
// the tunnel is up; a match attempt starts the login if it isn't.
//
// The destination is not resolved here: a name is matched as a name, an
// address as an address. Resolving every connection's name before the rules
// after this one would leak and slow down everything else.
type EasyConnect struct {
	Base
	name    string
	adapter string
}

func NewEasyConnect(name, adapter string) *EasyConnect {
	return &EasyConnect{name: name, adapter: adapter}
}

func (r *EasyConnect) RuleType() C.RuleType { return C.EasyConnectRule }
func (r *EasyConnect) Adapter() string      { return r.adapter }
func (r *EasyConnect) Payload() string      { return r.name }

func (r *EasyConnect) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	ec := easyconnect.LookupRouter(r.name)
	if ec == nil {
		return false, r.adapter
	}
	routing := ec.Routing()
	if routing == nil {
		return false, r.adapter
	}
	if host := metadata.RuleHost(); host != "" && routing.MatchHost(host) {
		return true, r.adapter
	}
	return routing.MatchIP(metadata.DstIP, metadata.DstPort, metadata.NetWork.String()), r.adapter
}

var _ C.Rule = (*EasyConnect)(nil)
