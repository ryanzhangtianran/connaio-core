package config

import (
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/sysdns"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/stretchr/testify/require"
)

func TestParseCapture(t *testing.T) {
	general := func() *General {
		g := &General{}
		g.MixedPort = 7899
		g.FindProcessMode = process.FindProcessStrict
		return g
	}

	g := general()
	g.Tun.Enable = true
	rules, err := parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureSystemProxy}}, g, nil)
	require.NoError(t, err)
	require.False(t, g.Tun.Enable)
	require.Empty(t, rules)

	g = general()
	_, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureTun}}, g, nil)
	require.NoError(t, err)
	require.True(t, g.Tun.Enable)

	g = general()
	rules, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureProcessTun, Processes: []string{"ghostty"}}}, g, nil)
	require.NoError(t, err)
	require.True(t, g.Tun.Enable)
	require.Len(t, rules, 1)
	require.Equal(t, C.CaptureFilter, rules[0].RuleType())

	g = general()
	g.MixedPort = 0
	_, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureSystemProxy}}, g, nil)
	require.Error(t, err)
	_, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureProcessTun}}, general(), nil)
	require.Error(t, err, "no processes")
	g = general()
	g.FindProcessMode = process.FindProcessOff
	_, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: CaptureProcessTun, Processes: []string{"ghostty"}}}, g, nil)
	require.Error(t, err, "find-process-mode off")
	_, err = parseCapture(&RawConfig{Capture: RawCapture{Mode: "nope"}}, general(), nil)
	require.Error(t, err)
}

func TestWithSystemResolvers(t *testing.T) {
	base := &DNS{
		Enable:             true,
		UseSystemResolvers: true,
		NameServerPolicy:   []dns.Policy{{Domain: "+.user.example"}},
		FakeIPSkipper:      &fakeip.Skipper{Mode: C.FilterBlackList},
	}
	resolvers := []sysdns.Resolver{{Domains: []string{"corp.example.com"}, Nameservers: []string{"udp://10.0.0.53:53#utun4"}}}

	d := base.WithSystemResolvers(resolvers)
	require.Len(t, d.NameServerPolicy, 2)
	require.Equal(t, "+.user.example", d.NameServerPolicy[0].Domain, "user policy stays first")
	sys := d.NameServerPolicy[1]
	require.True(t, sys.Matcher.MatchDomain("git.corp.example.com"))
	require.False(t, sys.Matcher.MatchDomain("example.com"))
	require.Equal(t, "10.0.0.53:53", sys.NameServers[0].Addr)
	require.Equal(t, "utun4", sys.NameServers[0].ProxyName, "bound to the VPN interface")
	require.True(t, d.FakeIPSkipper.ShouldSkipped("git.corp.example.com"), "real IP so the VPN route applies")
	require.False(t, d.FakeIPSkipper.ShouldSkipped("google.com"))
	require.Len(t, base.NameServerPolicy, 1, "base config untouched")
	require.False(t, base.FakeIPSkipper.ShouldSkipped("git.corp.example.com"))

	base.UseSystemResolvers = false
	require.Same(t, base, base.WithSystemResolvers(resolvers))
}
