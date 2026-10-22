package common

import (
	"path/filepath"
	"slices"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

// ProcessAncestor matches when the connection's process or any of its ancestors has the given
// executable name (PROCESS-ANCESTOR) or path (PROCESS-ANCESTOR-PATH), e.g. everything started in a terminal.
type ProcessAncestor struct {
	Base
	pattern  string
	adapter  string
	ruleType C.RuleType
}

func (pa *ProcessAncestor) Payload() string      { return pa.pattern }
func (pa *ProcessAncestor) Adapter() string      { return pa.adapter }
func (pa *ProcessAncestor) RuleType() C.RuleType { return pa.ruleType }

func (pa *ProcessAncestor) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	return slices.ContainsFunc(processChain(metadata), pa.match), pa.adapter
}

// processChain is the process's own path followed by its ancestors', as the tunnel's FindProcess
// filled them in (none without a pid).
func processChain(metadata *C.Metadata) []string {
	return append([]string{metadata.ProcessPath}, metadata.ProcessAncestors...)
}

func (pa *ProcessAncestor) match(path string) bool {
	if path == "" {
		return false
	}
	if pa.ruleType == C.ProcessAncestorPath {
		return strings.EqualFold(path, pa.pattern)
	}
	return strings.EqualFold(filepath.Base(path), pa.pattern)
}

func NewProcessAncestor(pattern string, adapter string, ruleType C.RuleType) (*ProcessAncestor, error) {
	return &ProcessAncestor{pattern: pattern, adapter: adapter, ruleType: ruleType}, nil
}

// CaptureFilter implements capture.mode process-tun: TUN traffic that isn't from one of the
// listed processes (or their descendants) goes DIRECT ahead of every other rule.
type CaptureFilter struct {
	Base
	names     string
	processes []*ProcessAncestor
}

func NewCaptureFilter(names []string) *CaptureFilter {
	f := &CaptureFilter{names: strings.Join(names, ",")}
	for _, name := range names {
		f.processes = append(f.processes, &ProcessAncestor{pattern: name, ruleType: C.ProcessAncestor})
	}
	return f
}

func (f *CaptureFilter) Payload() string      { return f.names }
func (f *CaptureFilter) Adapter() string      { return "DIRECT" }
func (f *CaptureFilter) RuleType() C.RuleType { return C.CaptureFilter }

func (f *CaptureFilter) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if metadata.Type != C.TUN {
		return false, "DIRECT"
	}
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	chain := processChain(metadata)
	for _, pa := range f.processes {
		if slices.ContainsFunc(chain, pa.match) {
			return false, "DIRECT"
		}
	}
	return true, "DIRECT"
}

var (
	_ C.Rule = (*ProcessAncestor)(nil)
	_ C.Rule = (*CaptureFilter)(nil)
)
