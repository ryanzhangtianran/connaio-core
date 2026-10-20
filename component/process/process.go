package process

import (
	"errors"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

// FindProcess returns the uid, pid (0 where the platform doesn't report it) and executable path
// of the process owning the socket.
func FindProcess(network string, srcIP netip.Addr, srcPort int) (uid, pid uint32, path string, err error) {
	return findProcess(network, srcIP, srcPort)
}

const maxAncestorDepth = 64

// Ancestors returns the executable paths of pid's ancestors, nearest first, stopping before pid 1.
// It reads the live process table, so a reused pid can't yield a stale chain.
func Ancestors(pid uint32) ([]string, error) {
	var paths []string
	for range maxAncestorDepth {
		ppid, path, err := parentProcess(pid)
		if err != nil || ppid <= 1 {
			return paths, err
		}
		paths = append(paths, path)
		pid = ppid
	}
	return paths, nil
}

// PackageNameResolver
// never change type traits because it's used in CMFA
type PackageNameResolver func(metadata *C.Metadata) (string, error)

// DefaultPackageNameResolver
// never change type traits because it's used in CMFA
var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *C.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}
