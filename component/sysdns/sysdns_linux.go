package sysdns

func splitResolvers() ([]Resolver, error) {
	domains, err := output("resolvectl", "domain")
	if err != nil {
		return nil, nil // no systemd-resolved: nothing to follow
	}
	servers, err := output("resolvectl", "dns")
	if err != nil {
		return nil, err
	}
	return parseResolvectl(string(domains), string(servers)), nil
}

// resolvedDNS is `resolvectl dns`: the servers behind systemd-resolved's own 127.0.0.53.
func resolvedDNS() string {
	out, _ := output("resolvectl", "dns")
	return string(out)
}
