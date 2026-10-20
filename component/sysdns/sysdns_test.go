package sysdns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseScutil(t *testing.T) {
	got := parseScutil(`DNS configuration

resolver #1
  nameserver[0] : 8.8.8.8
  if_index : 11 (en0)
  flags    : Request A records

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5

resolver #3
  domain   : 254.169.in-addr.arpa
  options  : mdns

resolver #4
  domain   : corp.example.com
  nameserver[0] : 10.0.0.53
  nameserver[1] : fd00::53%utun4
  if_index : 23 (utun4)
  flags    : Supplemental, Request A records

resolver #5
  domain   : tail1234.ts.net.
  nameserver[0] : 100.100.100.100
  if_index : 24 (utun5)

DNS configuration (for scoped queries)

resolver #1
  domain   : scoped.example.com
  nameserver[0] : 10.9.9.9
`)
	require.Equal(t, []Resolver{
		{Domains: []string{"corp.example.com"}, Nameservers: []string{"udp://10.0.0.53:53#utun4", "udp://[fd00::53]:53#utun4"}},
		{Domains: []string{"tail1234.ts.net"}, Nameservers: []string{"udp://100.100.100.100:53#utun5"}},
	}, got)
}

func TestParseResolvectl(t *testing.T) {
	got := parseResolvectl(`Global: ~.
Link 2 (eth0): lan
Link 5 (tailscale0): ~ts.net tail1234.ts.net
Link 7 (wg0):
`, `Global: 1.1.1.1
Link 2 (eth0):
Link 5 (tailscale0): 100.100.100.100
Link 7 (wg0): 10.8.0.1
`)
	require.Equal(t, []Resolver{
		{Domains: []string{"ts.net", "tail1234.ts.net"}, Nameservers: []string{"udp://100.100.100.100:53#tailscale0"}},
	}, got)
}
