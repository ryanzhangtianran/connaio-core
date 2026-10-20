package route

import (
	"fmt"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	r.Get("/temporary", getTempRules)
	if !embedMode { // disallow update/patch rules in embed mode
		r.Patch("/disable", disableRules)
		r.Post("/temporary", addTempRule)
		r.Delete("/temporary", deleteTempRule)
		r.Delete("/temporary/{id}", deleteTempRule)
	}
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`

	// Extra contains information from RuleWrapper
	Extra *RuleExtra `json:"extra,omitempty"`
}

type RuleExtra struct {
	Disabled  bool      `json:"disabled"`
	HitCount  uint64    `json:"hitCount"`
	HitAt     time.Time `json:"hitAt"`
	MissCount uint64    `json:"missCount"`
	MissAt    time.Time `json:"missAt"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := tunnel.Rules()
	rules := make([]Rule, 0, len(rawRules))
	for index, rule := range rawRules {
		rules = append(rules, ruleInfo(index, rule))
	}

	render.JSON(w, r, render.M{
		"rules": rules,
	})
}

func ruleInfo(index int, rule constant.Rule) Rule {
	r := Rule{
		Index:   index,
		Type:    rule.RuleType().String(),
		Payload: rule.Payload(),
		Proxy:   rule.Adapter(),
		Size:    -1,
	}
	if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
		r.Extra = &RuleExtra{
			Disabled:  ruleWrapper.IsDisabled(),
			HitCount:  ruleWrapper.HitCount(),
			HitAt:     ruleWrapper.HitAt(),
			MissCount: ruleWrapper.MissCount(),
			MissAt:    ruleWrapper.MissAt(),
		}
		rule = ruleWrapper.Unwrap() // unwrap RuleWrapper
	}
	if rule.RuleType() == constant.GEOIP || rule.RuleType() == constant.GEOSITE {
		r.Size = rule.(constant.RuleGroup).GetRecodeSize()
	}
	return r
}

// getTempRules lists temporary rules in match order; index is the id for DELETE.
func getTempRules(w http.ResponseWriter, r *http.Request) {
	temp := tunnel.TempRules()
	rules := make([]Rule, 0, len(temp))
	for _, t := range temp {
		rules = append(rules, ruleInfo(t.ID, t.Rule))
	}
	render.JSON(w, r, render.M{"rules": rules})
}

// addTempRule adds a runtime-only rule, e.g. {"rule": "DOMAIN-SUFFIX,google.com,DIRECT"}. It matches
// ahead of the configured rules until removed or the config is reloaded.
func addTempRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule string `json:"rule"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	rule, err := parseTempRule(req.Rule)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.JSON(w, r, render.M{"id": tunnel.AddTempRule(RW.NewRuleWrapper(rule))})
}

// parseTempRule validates a rule line like the config's rules section does.
func parseTempRule(line string) (constant.Rule, error) {
	tp, payload, target, params := RC.ParseRulePayload(line, true)
	if target == "" {
		return nil, fmt.Errorf("rule [%s] format invalid", line)
	}
	if _, ok := tunnel.Proxies()[target]; !ok {
		return nil, fmt.Errorf("rule [%s]: proxy [%s] not found", line, target)
	}
	rule, err := R.ParseRule(tp, payload, target, params, nil)
	if err != nil {
		return nil, fmt.Errorf("rule [%s]: %w", line, err)
	}
	for _, name := range rule.ProviderNames() {
		if _, ok := tunnel.RuleProviders()[name]; !ok {
			return nil, fmt.Errorf("rule [%s]: rule set [%s] not found", line, name)
		}
	}
	return rule, nil
}

// deleteTempRule removes /temporary/{id}, or every temporary rule without an id.
func deleteTempRule(w http.ResponseWriter, r *http.Request) {
	id := 0
	if s := chi.URLParam(r, "id"); s != "" {
		var err error
		if id, err = strconv.Atoi(s); err != nil || id <= 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
	}
	if !tunnel.RemoveTempRule(id) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}
	render.NoContent(w, r)
}

// disableRules disable or enable rules by their indexes.
func disableRules(w http.ResponseWriter, r *http.Request) {
	// key: rule index, value: disabled
	var payload map[int]bool
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if len(payload) != 0 {
		rules := tunnel.Rules()
		for index, disabled := range payload {
			if index < 0 || index >= len(rules) {
				continue
			}
			rule := rules[index]
			if ruleWrapper, ok := rule.(constant.RuleWrapper); ok {
				ruleWrapper.SetDisabled(disabled)
			}
		}
	}

	render.NoContent(w, r)
}
