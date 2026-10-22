package sysdns

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// nameservers is the system's resolvers as last read, kept for a few seconds: a lookup on every
// packet to port 53 would read the file each time.
var nameservers struct {
	sync.Mutex
	list []netip.Addr
	at   time.Time
}

// IsNameserver says whether ip is one of the system's own resolvers: on macOS and Linux those in
// /etc/resolv.conf (macOS keeps it in step with the network's), on Linux also the ones
// systemd-resolved forwards to from its 127.0.0.53, none elsewhere.
func IsNameserver(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	nameservers.Lock()
	defer nameservers.Unlock()
	if time.Since(nameservers.at) > 10*time.Second {
		nameservers.list, nameservers.at = append(readResolvConf("/etc/resolv.conf"), parseResolvectlDNS(resolvedDNS())...), time.Now()
	}
	for _, ns := range nameservers.list {
		if ns == ip.Unmap() {
			return true
		}
	}
	return false
}

func readResolvConf(path string) []netip.Addr {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 1 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, ip.WithZone("").Unmap())
			}
		}
	}
	return out
}

// parseResolvectlDNS reads `resolvectl dns`, a line per link: "Link 2 (eth0): 10.0.0.1 fd00::1".
func parseResolvectlDNS(out string) []netip.Addr {
	var addrs []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, f := range strings.Fields(rest) {
			if ip, err := netip.ParseAddr(f); err == nil {
				addrs = append(addrs, ip.WithZone("").Unmap())
			}
		}
	}
	return addrs
}
