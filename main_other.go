//go:build !windows

package main

// runAsService reports false: only Windows has a service manager to answer to.
func runAsService() bool { return false }
