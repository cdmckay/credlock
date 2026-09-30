// The menu bar icon, in menubar_darwin.m. Snapshots are JSON (see menubar.go).

// credlock_menubar_run runs the icon on the main thread until quit.
void credlock_menubar_run(void);

// credlock_menubar_update shows a snapshot. It may be called from any thread.
void credlock_menubar_update(const char *json);

// credlock_menubar_icon_snapshot renders the icon, at rest and being read, on
// a menu bar coloured strip, to a PNG.
int credlock_menubar_icon_snapshot(const char *path, int dark);

// credlock_menubar_quit ends credlock_menubar_run, and with it the process.
void credlock_menubar_quit(void);
