// The tray icon on Linux, in menubar_sni.c: a StatusNotifierItem with a
// com.canonical.dbusmenu menu, on the session bus. menubar_sni.go builds
// what it shows; clicks go back through credlockTrayEvent.

// credlock_tray_run serves the icon until credlock_tray_quit. It returns
// nonzero if it can't reach the session bus.
int credlock_tray_run(const char *icon_dir);

// credlock_tray_update shows a new menu, given as GVariant text of type
// (ia{sv}av), with its icon, the label beside it, its tooltip, and whether
// it shows at all. It may be called from any thread.
void credlock_tray_update(const char *layout, const char *icon, const char *label, const char *tooltip,
                          int active);

// credlock_tray_quit ends credlock_tray_run. It may be called from any
// thread, even before credlock_tray_run has started.
void credlock_tray_quit(void);

// credlock_tray_layout_ok says whether layout parses as a menu.
int credlock_tray_layout_ok(const char *layout);
