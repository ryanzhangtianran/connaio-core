package route

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// flushSystemDNS flushes macOS's DNS cache, which takes root. A root core does it for its GUI, whose
// socket only admins reach, so the GUI needs no administrator prompt; elsewhere it answers 501.
func flushSystemDNS(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		render.Status(r, http.StatusNotImplemented)
		render.JSON(w, r, newError("only a root core on macOS flushes the system's DNS cache"))
		return
	}
	for _, cmd := range [][]string{{"dscacheutil", "-flushcache"}, {"killall", "-HUP", "mDNSResponder"}} {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(strings.Join(cmd, " ")+": "+strings.TrimSpace(string(out))+" "+err.Error()))
			return
		}
	}
	render.NoContent(w, r)
}
