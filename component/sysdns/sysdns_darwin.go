package sysdns

import "os/exec"

func splitResolvers() ([]Resolver, error) {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil, err
	}
	return parseScutil(string(out)), nil
}
