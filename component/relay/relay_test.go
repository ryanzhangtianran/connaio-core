package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	require.Equal(t, "10.8.0.1", Address(netip.MustParseAddr("10.8.0.2")).String())
	require.Equal(t, "10.8.0.254", Address(netip.MustParseAddr("10.8.0.1")).String())
}

// TestRunErrors: a config the relay can't serve fails at once, for its service to report.
func TestRunErrors(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	for name, cfg := range map[string]Config{
		"short password": {Password: "1234567", Peer: "10.8.0.2"},
		"bad peer":       {Password: "12345678", Peer: "vps"},
		"bad forward":    {Password: "12345678", Peer: "10.8.0.2", Forwards: []string{"8080"}},
		"port taken":     {Password: "12345678", Peer: "10.8.0.2", Forwards: []string{busy.Addr().String()}},
	} {
		require.Error(t, Run(context.Background(), cfg), name)
	}
}

// TestCheck: under a done context Run only sets up and returns, as connaio-relay -check: a config
// that can be served passes, one whose port is taken fails.
func TestCheck(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := free.Addr().String()
	free.Close()
	require.NoError(t, Run(done, Config{Password: "12345678", Peer: "10.8.0.2", Forwards: []string{addr}}))
	busy, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	defer busy.Close()
	require.Error(t, Run(done, Config{Password: "12345678", Peer: "10.8.0.2", Forwards: []string{addr}}))
}
