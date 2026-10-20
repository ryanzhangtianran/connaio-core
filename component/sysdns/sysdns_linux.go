package sysdns

import "os/exec"

func splitResolvers() ([]Resolver, error) {
	domains, err := exec.Command("resolvectl", "domain").Output()
	if err != nil {
		return nil, nil // no systemd-resolved: nothing to follow
	}
	servers, err := exec.Command("resolvectl", "dns").Output()
	if err != nil {
		return nil, err
	}
	return parseResolvectl(string(domains), string(servers)), nil
}
