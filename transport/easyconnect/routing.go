package easyconnect

import (
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Routing is what the gateway will route for this session, from
// /por/rclist.csp. Traffic outside the list is silently dropped by the
// gateway instead of refused, which looks like a hang, so the kernel sends
// only what is listed.
type Routing struct {
	IP      []Range  `json:"ip"`
	Domains []string `json:"domains"`
	DNS     []string `json:"dns"`
}

type Range struct {
	From     netip.Addr `json:"from"`
	To       netip.Addr `json:"to"`
	PortMin  uint16     `json:"portMin"`
	PortMax  uint16     `json:"portMax"`
	Protocol string     `json:"protocol"` // all, tcp, udp, icmp
}

// Key names a range as a client picks it: "from-to", or the one address.
func (rg Range) Key() string {
	if rg.From == rg.To {
		return rg.From.String()
	}
	return rg.From.String() + "-" + rg.To.String()
}

// Without is r less the ranges (by Key) and names in skip.
func (r Routing) Without(skip []string) Routing {
	if len(skip) == 0 {
		return r
	}
	r.IP = slices.DeleteFunc(slices.Clone(r.IP), func(rg Range) bool { return slices.Contains(skip, rg.Key()) })
	r.Domains = slices.DeleteFunc(slices.Clone(r.Domains), func(d string) bool { return slices.Contains(skip, d) })
	return r
}

// MatchHost reports whether host is one of the routed names, or under one.
func (r *Routing) MatchHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range r.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// MatchIP reports whether ip:port over network (tcp or udp) is routed.
func (r *Routing) MatchIP(ip netip.Addr, port uint16, network string) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, rg := range r.IP {
		if rg.Protocol != "all" && rg.Protocol != network {
			continue
		}
		if ip.Compare(rg.From) >= 0 && ip.Compare(rg.To) <= 0 && port >= rg.PortMin && port <= rg.PortMax {
			return true
		}
	}
	return false
}

// parseRouting reads /por/rclist.csp. Resources of type 1 and 2 are the
// routed ones. Hosts and ports are parallel lists separated by ';', and
// ranges use '~'.
func parseRouting(rclist string) Routing {
	var routing Routing
	domains := map[string]bool{}
	for _, rc := range elements(rclist, "Rc") {
		if t := rc["type"]; t != "1" && t != "2" {
			continue
		}
		protocol := map[string]string{"-1": "all", "0": "tcp", "1": "udp", "2": "icmp"}[rc["proto"]]
		hosts, ports := strings.Split(rc["host"], ";"), strings.Split(rc["port"], ";")
		if rc["host"] == "" || rc["port"] == "" || len(hosts) != len(ports) {
			continue
		}
		for i, host := range hosts {
			bounds := strings.Split(ports[i], "~")
			if len(bounds) != 2 {
				continue
			}
			lo, err1 := strconv.ParseUint(bounds[0], 10, 16)
			hi, err2 := strconv.ParseUint(bounds[1], 10, 16)
			if err1 != nil || err2 != nil {
				continue
			}
			portMin, portMax := uint16(lo), uint16(hi)
			if from, to, ok := strings.Cut(host, "~"); ok {
				a, err1 := netip.ParseAddr(from)
				b, err2 := netip.ParseAddr(to)
				if err1 == nil && err2 == nil && a.Is4() && b.Is4() {
					routing.IP = append(routing.IP, Range{a, b, portMin, portMax, protocol})
				}
				continue
			}
			name := host
			if i := strings.LastIndex(name, "//"); i >= 0 {
				name = name[i+2:]
			}
			name, _, _ = strings.Cut(name, "/")
			name = strings.ReplaceAll(name, "*", "")
			var portText string
			if parts := strings.Split(name, ":"); len(parts) == 2 {
				name, portText = parts[0], parts[1]
			}
			if ip, err := netip.ParseAddr(name); err == nil && ip.Is4() {
				if p, err := strconv.ParseUint(portText, 10, 16); err == nil {
					portMin, portMax = uint16(p), uint16(p)
				}
				routing.IP = append(routing.IP, Range{ip, ip, portMin, portMax, protocol})
			} else if name = strings.ToLower(strings.Trim(name, ".")); name != "" {
				domains[name] = true
			}
		}
	}
	routing.Domains = slices.Sorted(maps.Keys(domains))
	if dns := elements(rclist, "Dns"); len(dns) > 0 {
		for _, s := range strings.Split(dns[0]["dnsserver"], ";") {
			if s = strings.TrimSpace(s); s != "" && s != "0.0.0.0" {
				routing.DNS = append(routing.DNS, s)
			}
		}
	}
	return routing
}

var attribute = regexp.MustCompile(`(\w+)="([^"]*)"`)

// elements is the attributes of every <tag ...> in text.
func elements(text, tag string) []map[string]string {
	var found []map[string]string
	for _, m := range regexp.MustCompile(`<`+tag+`\s([^>]*)>`).FindAllStringSubmatch(text, -1) {
		attrs := map[string]string{}
		for _, kv := range attribute.FindAllStringSubmatch(m[1], -1) {
			attrs[kv[1]] = strings.ReplaceAll(kv[2], "&amp;", "&")
		}
		found = append(found, attrs)
	}
	return found
}
