//go:build !darwin && !linux

package sysdns

func splitResolvers() ([]Resolver, error) { return nil, nil }

func resolvedDNS() string { return "" }
