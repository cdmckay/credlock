//go:build linux && !gtk

package platform

// hasWindow says whether this build has credlock's approval window. On Linux
// it is GTK 4, behind the gtk build tag; without it credlock only asks a hub.
const hasWindow = false
