//go:build !darwin && !linux

package outboundgroup

// readNetwork is only implemented on macOS and Linux; elsewhere subnet groups use their default.
func readNetwork() Network { return Network{} }

func prepareNetwork() {}
