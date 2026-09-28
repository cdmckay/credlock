// Package platform holds what credlock needs from the operating system: where
// the helper's socket lives, and who is on the other end of it. macOS is
// implemented; other systems get a stub that says so.
package platform

// Peer is the process on the other end of a connection, as the kernel reports
// it rather than as the process claims.
type Peer struct {
	UID  int
	PID  int
	Name string // the executable's short name, for showing to people
}
