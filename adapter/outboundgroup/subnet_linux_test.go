package outboundgroup

import "testing"

func TestLinuxNetworkParsing(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n" +
		"enp3s0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\n"
	if iface, gw := defaultRoute(route); iface != "enp3s0" || gw != "10.0.0.1" {
		t.Fatalf("%s %s", iface, gw)
	}
	ssid, bssid := activeWiFi("no:Other:11\\:22\\:33\\:44\\:55\\:66\nyes:Home\\: 5G:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n")
	if ssid != "Home: 5G" || bssid != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("%q %q", ssid, bssid)
	}
}
