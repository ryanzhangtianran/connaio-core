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
