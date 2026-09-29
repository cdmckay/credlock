// The approval window, in window_darwin.m. Both functions take the window's
// content as View JSON (see window.go).

#define CREDLOCK_WINDOW_ERROR (-1)
#define CREDLOCK_WINDOW_DENY 0
#define CREDLOCK_WINDOW_ALLOW 1
#define CREDLOCK_WINDOW_TIMED_OUT 2

// credlock_window_run shows the window and waits for an answer.
int credlock_window_run(const char *json);

// credlock_window_snapshot renders the window to a PNG without showing it.
// It returns 0 on success.
int credlock_window_snapshot(const char *json, const char *path, int dark);
