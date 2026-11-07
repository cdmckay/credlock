// Package platform holds what credlock needs from the operating system: where
// the helper's socket lives, who is on the other end of it, and keeping the
// helper's memory its own. macOS and Linux are implemented; other systems get
// a stub that says so.
package platform

// HelperSwitch is the environment variable that turns the helper on, on
// Linux. Until credlock has an approval window of its own there, the helper
// asks in a zenity dialog, which can't keep all of the window's rules, so it
// is off unless this is 1.
const HelperSwitch = "CREDLOCK_LINUX_HELPER"

// Peer is the process on the other end of a connection, as the kernel reports
// it rather than as the process claims.
type Peer struct {
	UID  int
	PID  int
	Name string // the executable's short name, for showing to people
}
