package tunnel

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/stretchr/testify/require"
)

func TestTempRules(t *testing.T) {
	configured := []C.Rule{RC.NewCaptureFilter([]string{"ghostty"}), RC.NewDomainSuffix("example.com", "CFG")}
	UpdateRules(configured, nil, nil)
	defer UpdateRules(nil, nil, nil)

	a := AddTempRule(RC.NewDomainSuffix("example.com", "A"))
	b := AddTempRule(RC.NewDomainSuffix("example.com", "B"))
	adapters := func() (out []string) {
		for _, r := range getRules(&C.Metadata{}) {
			out = append(out, r.Adapter())
		}
		return
	}
	// the process-tun scope stays first, then temporary rules newest first, then the config
	require.Equal(t, []string{"DIRECT", "B", "A", "CFG"}, adapters())
	require.Equal(t, b, TempRules()[0].ID)

	require.True(t, RemoveTempRule(b))
	require.False(t, RemoveTempRule(b))
	require.Equal(t, []string{"DIRECT", "A", "CFG"}, adapters())
	require.Len(t, Rules(), 2, "configured rules untouched")

	UpdateRules(configured, nil, nil) // a reload drops temporary rules
	require.Empty(t, TempRules())
	require.False(t, RemoveTempRule(a))
}

func TestOutsideCaptureScope(t *testing.T) {
	defer UpdateRules(nil, nil, nil)
	tun := &C.Metadata{Type: C.TUN} // no process found: outside the ghostty scope
	mixed := &C.Metadata{Type: C.HTTP}

	UpdateRules([]C.Rule{RC.NewDomainSuffix("example.com", "CFG")}, nil, nil)
	_, outside := outsideCaptureScope(tun, C.RuleMatchHelper{})
	require.False(t, outside, "no process-tun configured")

	UpdateRules([]C.Rule{RC.NewCaptureFilter([]string{"ghostty"})}, nil, nil)
	filter, outside := outsideCaptureScope(tun, C.RuleMatchHelper{})
	require.True(t, outside)
	require.Equal(t, C.CaptureFilter, filter.RuleType())
	_, outside = outsideCaptureScope(mixed, C.RuleMatchHelper{})
	require.False(t, outside, "non-TUN inbounds follow global mode")
}
