// The approval window on Linux, in window_gtk.c. Both functions take the
// window's content as a View (see window.go) that window_gtk.go has already
// parsed and cleaned, so the window does nothing but lay it out.

#define CREDLOCK_WINDOW_ERROR (-1)
#define CREDLOCK_WINDOW_DENY 0
#define CREDLOCK_WINDOW_ALLOW 1
#define CREDLOCK_WINDOW_TIMED_OUT 2

typedef struct {
  const char *name;
  const char *ref;
} credlock_secret;

typedef struct {
  const char *kind;  // "", "pair" or "search"
  const char *title;
  const char *subtitle;
  const char *question;
  const char *reason;
  const char *command;
  const char *directory;
  const char *requester;
  const char *account;
  const char *lifetime;
  const char *secrets_title;
  const char *approved;
  const char *footer;
  const char *origin;
  const char *origin_title;
  const char *origin_note;
  const char *origin_tone;  // "remote" or "pair"
  const char *code;
  const char *code_note;
  const char *search;
  const char *search_note;
  const credlock_secret *secrets;
  int n_secrets;
  int timeout;  // seconds until it counts as Deny
} credlock_view;

// credlock_window_start sets up GTK and libadwaita, which read the desktop's
// settings, light or dark mode among them, from its portal. It returns
// nonzero without a display.
int credlock_window_start(void);

// credlock_window_run shows the window and waits for an answer. It starts
// GTK first if credlock_window_start hasn't.
int credlock_window_run(const credlock_view *v);

// credlock_window_snapshot renders the window to a PNG without showing it.
// It returns 0 on success.
int credlock_window_snapshot(const credlock_view *v, const char *path, int dark);
