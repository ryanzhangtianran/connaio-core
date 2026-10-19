package outbound

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/easyconnect"
)

// TestEasyConnectKicked: the gateway ending the session kickLimit times within kickWindow pauses
// logins until Reconnect; other losses and old kicks don't count.
func TestEasyConnectKicked(t *testing.T) {
	e := &EasyConnect{Base: &Base{name: "vpn"}, closed: true} // closed: Reconnect's kick starts no login here
	ended := fmt.Errorf("read: %w", easyconnect.ErrSessionEnded)
	lose := func(err error) {
		e.mu.Lock()
		e.noteLost(err)
		e.mu.Unlock()
	}
	lose(errors.New("i/o timeout"))
	lose(ended)
	lose(ended)
	if e.kicked || e.waiting() {
		t.Fatalf("paused after %d kicks", len(e.kicks))
	}
	if st := e.Status(); st.Kicks != 2 || st.LastKick.IsZero() {
		t.Fatalf("status reports %d kicks, last %v", st.Kicks, st.LastKick)
	}
	e.kicks = append([]time.Time{time.Now().Add(-kickWindow - time.Minute)}, e.kicks...) // an old one drops out
	lose(ended)
	if !e.kicked || !e.waiting() || !e.Status().Kicked {
		t.Fatalf("not paused after %d kicks in the window: %v", len(e.kicks), e.kicks)
	}
	e.Reconnect()
	if e.kicked || e.lastError != nil || len(e.kicks) != 0 {
		t.Fatal("Reconnect left the pause")
	}
}
