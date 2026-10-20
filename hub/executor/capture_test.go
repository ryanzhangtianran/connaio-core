package executor

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestProcessTunConfig(t *testing.T) {
	cfg, err := ParseWithBytes([]byte(`
mixed-port: 7899
rules:
  - MATCH,DIRECT
capture:
  mode: process-tun
  processes: [ghostty]
`))
	require.NoError(t, err)
	require.True(t, cfg.General.Tun.Enable)
	require.Empty(t, cfg.General.Tun.DNSHijack, "DNS stays with the system")
	require.True(t, cfg.Sniffer.Enable)
	require.Len(t, cfg.Sniffer.Sniffers, 3)
	require.Equal(t, C.CaptureFilter, cfg.Rules[0].RuleType())
}
