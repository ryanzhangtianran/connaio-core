package outboundgroup

import (
	"net/netip"
	"runtime"
	"slices"
	"testing"
)

func TestMatchNetwork(t *testing.T) {
	rules := map[string]string{
		"SSID:Home":         "DIRECT",
		"ROUTER:10.0.0.1":   "HOME",
		"192.168.100.0/24":  "LAN",
		"TYPE:WIRED":        "WIRED",
		"BSSID:AA:BB:CC:00": "AP",
	}
	cases := []struct {
		n    Network
		want string
	}{
		{Network{SSID: "Home", Router: "10.0.0.1"}, "DIRECT"}, // SSID beats ROUTER
		{Network{BSSID: "aa:bb:cc:00"}, "AP"},                 // BSSID is case-insensitive
		{Network{Router: "10.0.0.1", Wired: true}, "HOME"},
		{Network{Addrs: []netip.Addr{netip.MustParseAddr("192.168.100.11")}}, "LAN"},
		{Network{Wired: true}, "WIRED"},
		{Network{SSID: "Cafe", WiFi: true}, "PROXY"},
	}
	for _, c := range cases {
		if got := matchNetwork(c.n, rules, "PROXY"); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.n, got, c.want)
		}
	}
}

func TestSubnetMembers(t *testing.T) {
	got := subnetMembers(map[string]any{
		"default": "GIA",
		"rules":   map[string]any{"SSID:A": "DIRECT", "SSID:B": "DIRECT", "SSID:C": "HOME"},
	})
	if !slices.Equal(got, []any{"GIA", "DIRECT", "HOME"}) {
		t.Fatalf("members %v", got)
	}
}

func TestCurrentNetwork(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("macOS and Linux only")
	}
	n := readNetwork()
	if n.Router == "" || len(n.Addrs) == 0 {
		t.Skipf("no default route here: %+v", n)
	}
	t.Logf("%+v", n)
}
