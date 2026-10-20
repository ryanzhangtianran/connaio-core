package constant

var (
	Meta       = true
	Version    = "1.10.0"
	BuildTime  = "unknown time"
	MihomoName = "mihomo"
)

// ConnaioAPI is the controller API level GET /version reports for the Connaio GUI, which warns when
// its core is older than it needs. Bump it with every endpoint or behaviour the GUI starts to rely
// on. 1: capture modes, reverse tunnels, temporary rules, subnet groups, /network, /restart, and
// /proxies/{name}/udp and /nat.
const ConnaioAPI = 1
