//go:build !darwin && !linux

package process

import "net/netip"

func findProcess(network string, ip netip.Addr, srcPort int) (uint32, uint32, string, error) {
	uid, path, err := findProcessName(network, ip, srcPort)
	return uid, 0, path, err
}

func parentProcess(uint32) (uint32, string, error) {
	return 0, "", ErrPlatformNotSupport
}
