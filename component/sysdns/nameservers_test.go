package sysdns

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestReadResolvConf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("# macOS\nnameserver 2400:86e0:0:be6::3\nnameserver 10.90.63.2\nsearch lan\nnameserver fe80::1%en0\n"), 0o644)
	got := readResolvConf(p)
	want := []netip.Addr{netip.MustParseAddr("2400:86e0:0:be6::3"), netip.MustParseAddr("10.90.63.2"), netip.MustParseAddr("fe80::1")}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseResolvectlDNS(t *testing.T) {
	got := parseResolvectlDNS("Global:\nLink 2 (wlp2s0): 192.168.1.1 fd00::1\nLink 5 (tun0): 10.0.0.53\nLink 6 (docker0):\n")
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.53")}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}
