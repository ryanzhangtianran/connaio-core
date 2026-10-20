package route

import (
	"github.com/metacubex/mihomo/component/reverse"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func reverseTunnelRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, render.M{"tunnels": reverse.Statuses()})
	})
	return r
}
