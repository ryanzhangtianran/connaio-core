// Package sysdns reads the OS's per-domain ("split") resolvers, such as those a corporate VPN or
// Tailscale MagicDNS installs, so mihomo can keep sending those domains to the right server.
package sysdns

import (
	"net"
	"strings"
)

type Resolver struct {
	Domains     []string
	Nameservers []string // mihomo nameserver syntax, bound to the resolver's interface: udp://10.0.0.53:53#utun4
}

// SplitResolvers returns the current per-domain resolvers; nil where the platform has none or isn't supported.
func SplitResolvers() ([]Resolver, error) {
	return splitResolvers()
}

// nameserver formats ip (zone stripped, the interface binding covers it) for mihomo's parseNameServer.
func nameserver(ip, iface string) string {
	ip, _, _ = strings.Cut(ip, "%")
	s := "udp://" + net.JoinHostPort(ip, "53")
	if iface != "" {
		s += "#" + iface
	}
	return s
}

// parseScutil keeps resolvers of the main section that have a domain and nameservers; mDNS ones
// (local, link-local reverse zones) have no nameserver and drop out.
func parseScutil(out string) []Resolver {
	out, _, _ = strings.Cut(out, "DNS configuration (for scoped queries)")
	var (
		resolvers []Resolver
		domain    string
		ips       []string
		iface     string
	)
	flush := func() {
		if domain != "" && len(ips) > 0 {
			r := Resolver{Domains: []string{domain}}
			for _, ip := range ips {
				r.Nameservers = append(r.Nameservers, nameserver(ip, iface))
			}
			resolvers = append(resolvers, r)
		}
		domain, ips, iface = "", nil, ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "resolver #") {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, " : ") // values hold IPv6 colons, so split on the spaced separator
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "domain":
			domain = strings.ToLower(strings.TrimSuffix(value, "."))
		case strings.HasPrefix(key, "nameserver["):
			ips = append(ips, value)
		case key == "if_index": // "23 (utun4)"
			if _, name, ok := strings.Cut(value, "("); ok {
				iface = strings.TrimSuffix(name, ")")
			}
		}
	}
	flush()
	return resolvers
}

// parseResolvectl pairs per-link domains and servers from `resolvectl domain` / `resolvectl dns`,
// lines like "Link 5 (tailscale0): ~ts.net". Global settings and the "~." default route are not split DNS.
func parseResolvectl(domainsOut, serversOut string) []Resolver {
	servers := perLink(serversOut)
	var resolvers []Resolver
	for link, fields := range perLinkOrdered(domainsOut) {
		var r Resolver
		for _, d := range fields {
			if d = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(d, "~"), ".")); d != "" {
				r.Domains = append(r.Domains, d)
			}
		}
		for _, ip := range servers[link.name] {
			r.Nameservers = append(r.Nameservers, nameserver(ip, link.iface))
		}
		if len(r.Domains) > 0 && len(r.Nameservers) > 0 {
			resolvers = append(resolvers, r)
		}
	}
	return resolvers
}

type link struct{ name, iface string }

func perLink(out string) map[string][]string {
	m := map[string][]string{}
	for l, fields := range perLinkOrdered(out) {
		m[l.name] = fields
	}
	return m
}

// perLinkOrdered yields "Link N (iface): a b c" lines in order, skipping Global.
func perLinkOrdered(out string) func(yield func(link, []string) bool) {
	return func(yield func(link, []string) bool) {
		for _, line := range strings.Split(out, "\n") {
			head, rest, ok := strings.Cut(line, "): ")
			if !ok || !strings.HasPrefix(head, "Link ") {
				continue
			}
			_, iface, _ := strings.Cut(head, "(")
			if !yield(link{name: head, iface: iface}, strings.Fields(rest)) {
				return
			}
		}
	}
}
