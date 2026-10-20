package route

import (
	"github.com/metacubex/mihomo/adapter/outboundgroup"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// networkRouter reports the network subnet groups match on; a root daemon can read the SSID
// that macOS hides from the GUI.
func networkRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, outboundgroup.CurrentNetwork())
	})
	return r
}
