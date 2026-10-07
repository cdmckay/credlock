//go:build !darwin

package client

func installLoginItem() error { return nil }
func removeLoginItem() error  { return nil }
