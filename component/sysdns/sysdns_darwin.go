package sysdns

func splitResolvers() ([]Resolver, error) {
	out, err := output("scutil", "--dns")
	if err != nil {
		return nil, err
	}
	return parseScutil(string(out)), nil
}

func resolvedDNS() string { return "" }
