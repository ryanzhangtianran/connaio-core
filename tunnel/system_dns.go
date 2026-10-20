package tunnel

import (
	"github.com/metacubex/mihomo/component/sysdns"
	C "github.com/metacubex/mihomo/constant"
)

// systemDNS sends a query to one of the system's own resolvers (port 53 to an address the
// network handed out) DIRECT, ahead of the rules and the mode. Through a proxy it reaches a
// resolver that serves only this network, the query goes unanswered, and every lookup on the
// machine waits on it: what the OS asks first may be one the rules never mention.
type systemDNS struct{}

func (systemDNS) RuleType() C.RuleType    { return C.SystemDNS }
func (systemDNS) Adapter() string         { return "DIRECT" }
func (systemDNS) Payload() string         { return "" }
func (systemDNS) ProviderNames() []string { return nil }
func (systemDNS) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	return metadata.DstPort == 53 && sysdns.IsNameserver(metadata.DstIP), "DIRECT"
}
