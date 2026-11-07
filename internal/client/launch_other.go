//go:build !linux

package client

// launchHelper starts the helper in its own session.
func launchHelper(exe string) error { return launchDetached(exe) }
