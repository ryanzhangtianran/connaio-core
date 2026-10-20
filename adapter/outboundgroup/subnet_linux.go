package outboundgroup

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func prepareNetwork() {}

// readNetwork reads the default route from /proc/net/route, the interface's addresses, and the
// connected Wi-Fi's SSID and BSSID from NetworkManager (nmcli), which Ubuntu's desktop uses.
// Without --rescan no, nmcli would scan the air every 30s and stall the link each time.
func readNetwork() Network {
	var n Network
	b, _ := os.ReadFile("/proc/net/route")
	iface, gw := defaultRoute(string(b))
	n.Router = gw
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
	_, err := os.Stat("/sys/class/net/" + iface + "/wireless")
	n.WiFi = err == nil
	n.Wired = !n.WiFi
	if n.WiFi {
		n.SSID, n.BSSID = activeWiFi(run("nmcli", "-t", "-f", "ACTIVE,SSID,BSSID", "device", "wifi", "--rescan", "no"))
	}
	return n
}

// defaultRoute is the lowest-metric default route's interface and gateway; /proc/net/route keeps
// addresses as little-endian hex.
func defaultRoute(table string) (iface, gateway string) {
	metric := -1
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[1] != "00000000" {
			continue
		}
		m, _ := strconv.Atoi(f[6])
		gw, err := hex.DecodeString(f[2])
		if err != nil || len(gw) != 4 || (metric >= 0 && m >= metric) {
			continue
		}
		iface, gateway, metric = f[0], net.IPv4(gw[3], gw[2], gw[1], gw[0]).String(), m
	}
	return iface, gateway
}

// activeWiFi picks the in-use network from `nmcli -t` lines like `yes:Home:AA\:BB\:CC\:DD\:EE\:FF`,
// where colons inside a field are escaped.
func activeWiFi(out string) (ssid, bssid string) {
	for _, line := range strings.Split(out, "\n") {
		var fields []string
		var cur strings.Builder
		for i := 0; i < len(line); i++ {
			switch {
			case line[i] == '\\' && i+1 < len(line):
				i++
				cur.WriteByte(line[i])
			case line[i] == ':':
				fields = append(fields, cur.String())
				cur.Reset()
			default:
				cur.WriteByte(line[i])
			}
		}
		fields = append(fields, cur.String())
		if len(fields) == 3 && fields[0] == "yes" {
			return fields[1], fields[2]
		}
	}
	return "", ""
}
