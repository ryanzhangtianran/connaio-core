package easyconnect

import "sync"

// Router is what the EASYCONNECT rule needs from an outbound: the gateway's routing while the
// tunnel is up, nil otherwise (which starts the tunnel). The registry lives here rather than in
// the outbound package so the rule can use it without importing the outbounds.
type Router interface {
	Routing() *Routing
}

var routers struct {
	sync.Mutex
	byName map[string]Router
}

// SetRouters replaces the registry with the applied config's outbounds.
func SetRouters(byName map[string]Router) {
	routers.Lock()
	defer routers.Unlock()
	routers.byName = byName
}

// Routers is the registry as last set.
func Routers() map[string]Router {
	routers.Lock()
	defer routers.Unlock()
	return routers.byName
}

func LookupRouter(name string) Router {
	routers.Lock()
	defer routers.Unlock()
	return routers.byName[name]
}
