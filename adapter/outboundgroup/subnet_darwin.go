package outboundgroup

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
)

var verbose sync.Once

// prepareNetwork switches ipconfig to verbose once a subnet group exists in the root daemon, so
// its `ipconfig getsummary` shows the SSID and BSSID that macOS otherwise redacts.
func prepareNetwork() {
	verbose.Do(func() {
		if os.Geteuid() == 0 {
			go run("ipconfig", "setverbose", "1")
		}
	})
}

// readNetwork reads the default route and `ipconfig getsummary` for its interface. Only the root
// daemon sees SSID and BSSID; a user-level core gets them redacted, so only ROUTER, CIDR and TYPE
// rules match there.
func readNetwork() Network {
	var n Network
	route := run("route", "-n", "get", "default")
	iface := field(route, "interface", 0)
	n.Router = field(route, "gateway", 0)
	if iface == "" {
		return n
	}
	if ifc, err := net.InterfaceByName(iface); err == nil {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				n.Addrs = append(n.Addrs, p.Addr())
			}
		}
	}
	sum := run("ipconfig", "getsummary", iface)
	n.WiFi = field(sum, "InterfaceType", 2) == "WiFi"
	n.Wired = !n.WiFi && strings.HasPrefix(iface, "en") // a VPN's utun/ipsec/ppp default route is neither
	if v := field(sum, "SSID", 2); v != "<redacted>" {
		n.SSID = v
	}
	if v := field(sum, "BSSID", 2); v != "<redacted>" {
		n.BSSID = v
	}
	return n
}

// field finds "key : value" (or "key: value") on a line indented by exactly indent spaces.
func field(out, key string, indent int) string {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if len(line)-len(trimmed) != indent && indent > 0 {
			continue
		}
		if k, v, ok := strings.Cut(trimmed, ":"); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
