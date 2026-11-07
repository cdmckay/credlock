//go:build linux && gtk

// The approval window on Linux: GTK 4, styled through libadwaita so it
// follows the desktop's light and dark mode, and laid out in code to match the
// AppKit window in window_darwin.m. window_gtk.go starts it, and everything it
// shows arrives already cleaned.
//
// Deny is the default. Esc denies; every other key, Return included, does
// nothing, so typing that lands on the window can't approve anything. Allow
// takes a mouse click. It is no widget GTK can activate: it can't be focused,
// pressed from the keyboard, or pressed through the accessibility interface,
// which on Linux any program running as you can use without asking, and it is
// hidden from that interface besides. It is dimmed and ignores clicks for its
// first second on screen, so a click meant for another window can't land on
// it, and it ignores a click that lands while the window isn't active, which
// is the click that merely brings the window forward.

#include <adwaita.h>
#include <string.h>

#include "window_gtk.h"

// Layout, in pixels, as window_darwin.m's points.
enum {
  kWidth = 620,       // the window's width
  kMargin = 32,       // window edge to content
  kSection = 24,      // between the main blocks
  kIconGap = 14,      // icon to its text
  kColumnGap = 24,    // between side-by-side details
  kLabelGap = 4,      // a detail's title to its value
  kScrollAfter = 6,   // more secrets than this scroll
};

// The colours macOS calls system green, orange, teal and blue, light then
// dark, so the window reads the same on both systems. Everything else comes
// from libadwaita's own colours.
static const char *kLight =
    "@define-color cl_green #34c759; @define-color cl_orange #ff9500;"
    "@define-color cl_teal #30b0c7; @define-color cl_blue #007aff;";
static const char *kDark =
    "@define-color cl_green #30d158; @define-color cl_orange #ff9f0a;"
    "@define-color cl_teal #40c8e0; @define-color cl_blue #0a84ff;";

static const char *kStyle =
    ".cl-root { background-color: @window_bg_color; }"
    ".cl-dim { color: alpha(@window_fg_color, 0.62); }"
    ".cl-faint { color: alpha(@window_fg_color, 0.35); }"
    ".cl-title { font-size: 20px; font-weight: 700; }"
    ".cl-subtitle { font-size: 12px; font-weight: 500; }"
    ".cl-question { font-size: 17px; font-weight: 600; }"
    ".cl-green-text { color: @cl_green; }"
    ".cl-orange-text { color: @cl_orange; }"
    ".cl-teal-text { color: @cl_teal; }"
    // Cards: a tinted, rounded panel.
    ".cl-card { border-radius: 14px; padding: 20px; border: 1px solid transparent; }"
    ".cl-card.green { background-color: alpha(@cl_green, 0.07); border-color: alpha(@cl_green, 0.28); }"
    ".cl-card.orange { background-color: alpha(@cl_orange, 0.07); border-color: alpha(@cl_orange, 0.28); }"
    ".cl-card.teal { background-color: alpha(@cl_teal, 0.07); border-color: alpha(@cl_teal, 0.28); }"
    // Badges: an icon on a tile, round and tinted in the cards, plain and
    // square beside the details.
    ".cl-badge { border-radius: 9px; background-color: @card_bg_color;"
    "  border: 1px solid alpha(@window_fg_color, 0.12); color: alpha(@window_fg_color, 0.62); }"
    ".cl-badge.round { border-radius: 999px; border: none; }"
    ".cl-badge.round.green { background-color: alpha(@cl_green, 0.16); color: @cl_green; }"
    ".cl-badge.round.orange { background-color: alpha(@cl_orange, 0.16); color: @cl_orange; }"
    ".cl-detail-title { font-size: 12px; font-weight: 600; }"
    ".cl-mono { font-family: monospace; font-size: 12px; }"
    ".cl-plain { font-size: 12.5px; }"
    ".cl-reason-title { font-size: 12px; font-weight: 600; }"
    ".cl-reason { font-size: 15px; font-weight: 600; }"
    ".cl-card-title { font-size: 13px; font-weight: 600; }"
    ".cl-secret-name { font-family: monospace; font-size: 12.5px; font-weight: 600; }"
    ".cl-secret-ref { font-family: monospace; font-size: 11.5px; }"
    ".cl-note { font-size: 12px; }"
    ".cl-search-term { font-family: monospace; font-size: 17px; font-weight: 600; }"
    // Buttons: large and rounded. Deny is a GtkButton, so libadwaita's own
    // button look is cleared first.
    ".cl-button { border-radius: 12px; min-height: 58px; padding: 0; background-image: none;"
    "  box-shadow: none; outline: none; }"
    ".cl-button.secondary { background-color: @card_bg_color; color: @window_fg_color;"
    "  border: 1px solid alpha(@window_fg_color, 0.12); }"
    ".cl-button.secondary:hover { background-color: mix(@card_bg_color, @window_fg_color, 0.07); }"
    ".cl-button.secondary:active { background-color: mix(@card_bg_color, @window_fg_color, 0.18); }"
    ".cl-button.primary { background-color: mix(@cl_green, black, 0.12); color: white; border: none; }"
    ".cl-button.primary.armed:hover { background-color: mix(mix(@cl_green, black, 0.12), black, 0.07); }"
    ".cl-button.primary.pressed { background-color: mix(mix(@cl_green, black, 0.12), black, 0.18); }"
    ".cl-button.primary:not(.armed) { opacity: 0.4; }"
    ".cl-button-title { font-size: 15px; font-weight: 600; }"
    ".cl-button-hint { font-size: 11.5px; font-weight: 500; opacity: 0.8; }"
    ".cl-footer { font-size: 11.5px; }"
    ".cl-countdown { font-size: 11.5px; font-feature-settings: \"tnum\"; }";

enum { kUnanswered = -2 };

// The one window this process shows.
static struct {
  GtkWidget *window;
  GtkWidget *allow;
  GtkWidget *countdown;
  GtkCssProvider *colours;
  gboolean armed;
  gboolean pressing;
  guint timer;
  int left;
  int answer;
} w = {.answer = kUnanswered};

// Building blocks.

static const char *str(const char *s) { return s ? s : ""; }

static void classes(GtkWidget *widget, const char *names) {
  gchar **parts = g_strsplit(names, " ", -1);
  for (gchar **p = parts; *p; p++) {
    if (**p) {
      gtk_widget_add_css_class(widget, *p);
    }
  }
  g_strfreev(parts);
}

// text is a label that wraps at whatever width it is given. Its text is
// plain: nothing in it is read as markup.
static GtkWidget *text(const char *s, const char *css) {
  GtkWidget *l = gtk_label_new(str(s));
  GtkLabel *label = GTK_LABEL(l);
  gtk_label_set_wrap(label, TRUE);
  gtk_label_set_wrap_mode(label, PANGO_WRAP_WORD_CHAR);
  // A short natural width, so the label takes the width it is given rather
  // than asking for its whole text on one line.
  gtk_label_set_max_width_chars(label, 1);
  gtk_label_set_xalign(label, 0);
  gtk_widget_set_hexpand(l, TRUE);
  classes(l, css);
  return l;
}

// line is a label that doesn't wrap, and ends in "…" if it doesn't fit.
static GtkWidget *line(const char *s, const char *css) {
  GtkWidget *l = gtk_label_new(str(s));
  gtk_label_set_ellipsize(GTK_LABEL(l), PANGO_ELLIPSIZE_END);
  gtk_label_set_xalign(GTK_LABEL(l), 0);
  classes(l, css);
  return l;
}

// unseen is a widget the accessibility interface skips, children and all
// passed up to the nearest widget it shows.
static GtkWidget *unseen(GType type, const char *first, ...) {
  va_list args;
  va_start(args, first);
  GObject *o = g_object_new_valist(type, first, args);
  va_end(args);
  return GTK_WIDGET(o);
}

static GtkWidget *icon(const char *name, int size, const char *css) {
  GtkWidget *i = gtk_image_new_from_icon_name(name);
  gtk_image_set_pixel_size(GTK_IMAGE(i), size);
  classes(i, css);
  return i;
}

static GtkWidget *vbox(int spacing) { return gtk_box_new(GTK_ORIENTATION_VERTICAL, spacing); }

static GtkWidget *hbox(int spacing, GtkAlign valign) {
  GtkWidget *b = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, spacing);
  gtk_widget_set_valign(b, valign);
  return b;
}

static GtkWidget *add(GtkWidget *box, GtkWidget *child) {
  gtk_box_append(GTK_BOX(box), child);
  return child;
}

// badge is an icon on a tile: tinted and round in the cards (tint is the
// colour's class), plain and square beside the details (tint NULL).
static GtkWidget *badge(const char *name, int size, const char *tint) {
  GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
  gtk_widget_set_size_request(b, size, size);
  gtk_widget_set_valign(b, GTK_ALIGN_START);
  gtk_widget_set_halign(b, GTK_ALIGN_START);
  classes(b, "cl-badge");
  if (tint) {
    classes(b, "round");
    classes(b, tint);
    gtk_widget_set_valign(b, GTK_ALIGN_CENTER);
  }
  GtkWidget *i = icon(name, size * 44 / 100, "");
  gtk_widget_set_halign(i, GTK_ALIGN_CENTER);
  gtk_widget_set_valign(i, GTK_ALIGN_CENTER);
  gtk_widget_set_vexpand(i, TRUE);
  add(b, i);
  return b;
}

// card is a tinted, rounded panel around content.
static GtkWidget *card(const char *tint, GtkWidget *content) {
  GtkWidget *c = vbox(0);
  classes(c, "cl-card");
  classes(c, tint);
  add(c, content);
  return c;
}

// detail is one fact about the request: an icon, a small title, the value.
static GtkWidget *detail(const char *name, const char *title, const char *value, const char *css) {
  GtkWidget *row = hbox(kIconGap, GTK_ALIGN_START);
  gtk_widget_set_hexpand(row, TRUE);
  add(row, badge(name, 34, NULL));
  GtkWidget *words = add(row, vbox(kLabelGap));
  gtk_widget_set_hexpand(words, TRUE);
  add(words, text(title, "cl-detail-title cl-dim"));
  add(words, text(value, css));
  return row;
}

static GtkWidget *secret(const char *name, const char *ref) {
  GtkWidget *row = hbox(kIconGap, GTK_ALIGN_CENTER);
  add(row, badge("dialog-password-symbolic", 30, "green"));
  GtkWidget *words = add(row, vbox(3));
  gtk_widget_set_valign(words, GTK_ALIGN_CENTER);
  gtk_widget_set_hexpand(words, TRUE);
  add(words, text(name, "cl-secret-name"));
  add(words, text(ref, "cl-secret-ref cl-dim"));
  return row;
}

static GtkWidget *pair(GtkWidget *left, GtkWidget *right) {
  GtkWidget *row = hbox(kColumnGap, GTK_ALIGN_START);
  gtk_box_set_homogeneous(GTK_BOX(row), TRUE);
  add(row, left);
  add(row, right);
  return row;
}

// spaced gives a block its gap above, since the gaps between blocks differ.
static GtkWidget *spaced(GtkWidget *block, int above) {
  gtk_widget_set_margin_top(block, above);
  return block;
}

// Buttons.

static void answer(int a) {
  if (w.answer == kUnanswered) {
    w.answer = a;
  }
}

// face lays out a big button's face: an icon, its title, and a hint below.
// A face that isn't exposed is left out of the accessibility interface
// entirely, as Allow is: GTK shows a widget there again whenever it is
// mapped, so only a widget built with the presentation role stays out.
static GtkWidget *face(const char *name, const char *title, const char *hint, gboolean exposed) {
  GtkAccessibleRole box = exposed ? GTK_ACCESSIBLE_ROLE_GENERIC : GTK_ACCESSIBLE_ROLE_PRESENTATION;
  GtkAccessibleRole label = exposed ? GTK_ACCESSIBLE_ROLE_LABEL : GTK_ACCESSIBLE_ROLE_PRESENTATION;
  GtkAccessibleRole image = exposed ? GTK_ACCESSIBLE_ROLE_IMG : GTK_ACCESSIBLE_ROLE_PRESENTATION;
  GtkWidget *row = unseen(GTK_TYPE_BOX, "accessible-role", box, "orientation", GTK_ORIENTATION_HORIZONTAL,
                          "spacing", 10, "halign", GTK_ALIGN_CENTER, "valign", GTK_ALIGN_CENTER, NULL);
  add(row, unseen(GTK_TYPE_IMAGE, "accessible-role", image, "icon-name", name, "pixel-size", 17, NULL));
  GtkWidget *words = add(row, unseen(GTK_TYPE_BOX, "accessible-role", box, "orientation", GTK_ORIENTATION_VERTICAL,
                                     "spacing", 1, "valign", GTK_ALIGN_CENTER, NULL));
  GtkWidget *t = add(words, unseen(GTK_TYPE_LABEL, "accessible-role", label, "label", title, "xalign", 0.0f, NULL));
  classes(t, "cl-button-title");
  GtkWidget *h = add(words, unseen(GTK_TYPE_LABEL, "accessible-role", label, "label", hint, "xalign", 0.0f, NULL));
  classes(h, "cl-button-hint");
  return row;
}

static void on_deny(GtkButton *b, gpointer data) { answer(CREDLOCK_WINDOW_DENY); }

// Deny is a real button, which the accessibility interface can press: denying
// is always safe. It can't take the keyboard focus, so no key presses it.
static GtkWidget *deny_button(void) {
  GtkWidget *b = gtk_button_new();
  gtk_button_set_child(GTK_BUTTON(b), face("window-close-symbolic", "Deny", "Esc", TRUE));
  gtk_widget_set_focusable(b, FALSE);
  gtk_widget_set_focus_on_click(b, FALSE);
  gtk_widget_set_hexpand(b, TRUE);
  gtk_accessible_update_property(GTK_ACCESSIBLE(b), GTK_ACCESSIBLE_PROPERTY_LABEL, "Deny", -1);
  classes(b, "cl-button secondary");
  g_signal_connect(b, "clicked", G_CALLBACK(on_deny), NULL);
  return b;
}

static void arm(gboolean armed) {
  w.armed = armed;
  if (armed) {
    gtk_widget_add_css_class(w.allow, "armed");
  } else {
    gtk_widget_remove_css_class(w.allow, "armed");
  }
}

static void allow_pressed(GtkGestureClick *g, int n, double x, double y, gpointer data) {
  // Not yet armed, or the click that activates the window: not a press.
  if (!w.armed || !gtk_window_is_active(GTK_WINDOW(w.window))) {
    gtk_gesture_set_state(GTK_GESTURE(g), GTK_EVENT_SEQUENCE_DENIED);
    return;
  }
  w.pressing = TRUE;
  gtk_widget_add_css_class(w.allow, "pressed");
}

static void allow_released(GtkGestureClick *g, int n, double x, double y, gpointer data) {
  gboolean pressed = w.pressing;
  w.pressing = FALSE;
  gtk_widget_remove_css_class(w.allow, "pressed");
  // Only a release over the button counts, as with any button.
  if (pressed && w.armed && gtk_widget_contains(w.allow, x, y)) {
    answer(CREDLOCK_WINDOW_ALLOW);
  }
}

static void allow_stopped(GtkGestureClick *g, gpointer data) {
  w.pressing = FALSE;
  gtk_widget_remove_css_class(w.allow, "pressed");
}

// Allow is a plain box with a click gesture, not a button, and the
// accessibility interface doesn't see it: nothing but a pointer click can
// press it.
static GtkWidget *allow_button(void) {
  GtkWidget *b = unseen(GTK_TYPE_BOX, "accessible-role", GTK_ACCESSIBLE_ROLE_PRESENTATION, "orientation",
                        GTK_ORIENTATION_VERTICAL, NULL);
  add(b, face("object-select-symbolic", "Allow", "Click", FALSE));
  gtk_widget_set_valign(gtk_widget_get_first_child(b), GTK_ALIGN_CENTER);
  gtk_widget_set_vexpand(gtk_widget_get_first_child(b), TRUE);
  gtk_widget_set_focusable(b, FALSE);
  gtk_widget_set_hexpand(b, TRUE);
  classes(b, "cl-button primary");
  GtkGesture *click = gtk_gesture_click_new();
  gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(click), GDK_BUTTON_PRIMARY);
  g_signal_connect(click, "pressed", G_CALLBACK(allow_pressed), NULL);
  g_signal_connect(click, "released", G_CALLBACK(allow_released), NULL);
  g_signal_connect(click, "stopped", G_CALLBACK(allow_stopped), NULL);
  gtk_widget_add_controller(b, GTK_EVENT_CONTROLLER(click));
  return b;
}

// The window.

static char *remaining(int seconds) {
  return g_strdup_printf("Counts as Deny in %d:%02d", seconds / 60, seconds % 60);
}

static GtkWidget *build(const credlock_view *v) {
  // A search asks for no secret: teal, with the term where the secrets go.
  gboolean searching = strcmp(str(v->kind), "search") == 0;
  GtkWidget *root = vbox(0);
  classes(root, "cl-root");
  gtk_widget_set_size_request(root, kWidth - 2 * kMargin, -1);
  gtk_widget_set_margin_top(root, kMargin + 4);
  gtk_widget_set_margin_bottom(root, kMargin - 6);
  gtk_widget_set_margin_start(root, kMargin);
  gtk_widget_set_margin_end(root, kMargin);

  // Who is asking.
  GtkWidget *header = add(root, hbox(kIconGap, GTK_ALIGN_CENTER));
  add(header, icon(searching ? "system-search-symbolic" : "security-high-symbolic", 30,
                   searching ? "cl-teal-text" : "cl-green-text"));
  GtkWidget *titles = add(header, vbox(2));
  gtk_widget_set_valign(titles, GTK_ALIGN_CENTER);
  add(titles, line(v->title, "cl-title"));
  add(titles, line(v->subtitle, "cl-subtitle cl-dim"));

  add(root, spaced(text(v->question, "cl-question"), 20));

  // Why.
  GtkWidget *why = hbox(kIconGap, GTK_ALIGN_CENTER);
  add(why, badge("chat-message-new-symbolic", 42, "orange"));
  GtkWidget *because = add(why, vbox(kLabelGap));
  gtk_widget_set_valign(because, GTK_ALIGN_CENTER);
  add(because, text("Reason", "cl-reason-title cl-orange-text"));
  add(because, text(v->reason, "cl-reason"));
  add(root, spaced(card("orange", why), 18));

  // What, where and for how long. A search has no command to hand secrets
  // to: its answer goes back to the requester itself.
  GtkWidget *details = add(root, spaced(vbox(18), kSection));
  if (!searching) {
    add(details, detail("utilities-terminal-symbolic", "Command", v->command, "cl-mono"));
  }
  add(details, pair(detail("folder-symbolic", "Directory", v->directory, "cl-mono"),
                    detail("system-run-symbolic", "Requested by", v->requester, "cl-mono")));
  add(details, pair(detail("avatar-default-symbolic", "1Password account", v->account, "cl-plain"),
                    detail("alarm-symbolic", "Approval lasts", v->lifetime, "cl-plain")));

  // Which secrets, or what a search looks for.
  GtkWidget *last = details;
  if (searching) {
    GtkWidget *term = vbox(10);
    add(term, text("Searching item titles for", "cl-card-title cl-teal-text"));
    add(term, text(v->search, "cl-search-term"));
    add(term, text(v->search_note, "cl-note cl-dim"));
    last = add(root, spaced(card("teal", term), kSection));
  } else if (v->n_secrets > 0) {
    gboolean scrolls = v->n_secrets > kScrollAfter;
    GtkWidget *parts = vbox(16);
    char *title = g_strdup_printf("%s%s", str(v->secrets_title), scrolls ? " · scroll to see them all" : "");
    add(parts, text(title, "cl-card-title cl-green-text"));
    g_free(title);
    GtkWidget *rows = vbox(14);
    for (int i = 0; i < v->n_secrets; i++) {
      add(rows, secret(v->secrets[i].name, v->secrets[i].ref));
    }
    if (scrolls) {
      GtkWidget *sv = gtk_scrolled_window_new();
      gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sv), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
      gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sv), rows);
      gtk_widget_set_size_request(sv, -1, kScrollAfter * 44 + (kScrollAfter - 1) * 14);
      add(parts, sv);
    } else {
      add(parts, rows);
    }
    if (*str(v->approved)) {
      add(parts, text(v->approved, "cl-note cl-dim"));
    }
    last = add(root, spaced(card("green", parts), kSection));
  }
  (void)last;

  // The answer.
  GtkWidget *buttons = add(root, spaced(hbox(16, GTK_ALIGN_CENTER), 28));
  gtk_box_set_homogeneous(GTK_BOX(buttons), TRUE);
  add(buttons, deny_button());
  w.allow = add(buttons, allow_button());

  GtkWidget *footer = add(root, spaced(hbox(8, GTK_ALIGN_CENTER), 16));
  add(footer, icon("changes-prevent-symbolic", 11, "cl-faint"));
  add(footer, text(v->footer, "cl-footer cl-dim"));
  char *left = remaining(v->timeout);
  w.countdown = add(footer, line(left, "cl-countdown cl-dim"));
  g_free(left);
  gtk_widget_set_halign(w.countdown, GTK_ALIGN_END);
  return root;
}

static void load_style(void) {
  GtkCssProvider *style = gtk_css_provider_new();
  gtk_css_provider_load_from_string(style, kStyle);
  gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(style),
                                             GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
  w.colours = gtk_css_provider_new();
  gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(w.colours),
                                             GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}

// set_colours follows libadwaita's light or dark mode.
static void set_colours(AdwStyleManager *sm, GParamSpec *p, gpointer data) {
  gtk_css_provider_load_from_string(w.colours, adw_style_manager_get_dark(sm) ? kDark : kLight);
}

static gboolean on_key(GtkEventControllerKey *k, guint keyval, guint code, GdkModifierType mods, gpointer data) {
  if (keyval == GDK_KEY_Escape) {
    answer(CREDLOCK_WINDOW_DENY);
  }
  return TRUE;  // every other key, Return included, does nothing
}

static gboolean on_close(GtkWindow *win, gpointer data) {
  answer(CREDLOCK_WINDOW_DENY);
  return TRUE;  // closed below, once answered
}

// make_window puts root in a window of its size, with no title bar, which
// can be moved by dragging anywhere.
static GtkWidget *make_window(GtkWidget *root) {
  GtkWidget *win = adw_window_new();
  gtk_window_set_title(GTK_WINDOW(win), "credlock");
  gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
  GtkWidget *handle = gtk_window_handle_new();
  GtkWidget *background = vbox(0);
  classes(background, "cl-root");
  gtk_box_append(GTK_BOX(background), root);
  gtk_window_handle_set_child(GTK_WINDOW_HANDLE(handle), background);
  adw_window_set_content(ADW_WINDOW(win), handle);
  return win;
}

// start sets up GTK and libadwaita, once. It fails, rather than aborting,
// without a display.
static gboolean start(void) {
  static gboolean started;
  if (started) {
    return TRUE;
  }
  g_set_prgname("credlock");
  g_set_application_name("credlock");
  if (!gtk_init_check()) {
    return FALSE;
  }
  adw_init();
  load_style();
  AdwStyleManager *sm = adw_style_manager_get_default();
  set_colours(sm, NULL, NULL);
  g_signal_connect(sm, "notify::dark", G_CALLBACK(set_colours), NULL);
  started = TRUE;
  return TRUE;
}

int credlock_window_start(void) { return start() ? 0 : -1; }

static gboolean tick(gpointer data) {
  w.left--;
  arm(TRUE);  // after a second on screen
  char *left = remaining(w.left > 0 ? w.left : 0);
  gtk_label_set_text(GTK_LABEL(w.countdown), left);
  g_free(left);
  if (w.left <= 0) {
    answer(CREDLOCK_WINDOW_TIMED_OUT);
    w.timer = 0;
    return G_SOURCE_REMOVE;
  }
  return G_SOURCE_CONTINUE;
}

int credlock_window_run(const credlock_view *v) {
  if (!start()) {
    return CREDLOCK_WINDOW_ERROR;
  }
  w.left = v->timeout > 0 ? v->timeout : 120;
  w.window = make_window(build(v));
  arm(FALSE);

  GtkEventController *keys = gtk_event_controller_key_new();
  gtk_event_controller_set_propagation_phase(keys, GTK_PHASE_CAPTURE);
  g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key), NULL);
  gtk_widget_add_controller(w.window, keys);
  g_signal_connect(w.window, "close-request", G_CALLBACK(on_close), NULL);

  w.timer = g_timeout_add_seconds(1, tick, NULL);
  gtk_window_present(GTK_WINDOW(w.window));
  while (w.answer == kUnanswered) {
    g_main_context_iteration(NULL, TRUE);
  }
  if (w.timer) {
    g_source_remove(w.timer);
  }
  gtk_window_destroy(GTK_WINDOW(w.window));
  while (g_main_context_iteration(NULL, FALSE)) {
  }
  return w.answer;
}

// Snapshots.

// The window is drawn once it is on screen: GTK only renders what is mapped.
// So a snapshot shows the window for a moment, unlike the Mac's.
static struct {
  const char *path;
  gboolean done;
  gboolean ok;
} shot;

static void after_paint(GdkFrameClock *clock, gpointer root) {
  if (shot.done) {
    return;
  }
  shot.done = TRUE;
  GtkWidget *content = GTK_WIDGET(root);
  int width = gtk_widget_get_width(content);
  int height = gtk_widget_get_height(content);
  GdkPaintable *paint = gtk_widget_paintable_new(content);
  GtkSnapshot *s = gtk_snapshot_new();
  gdk_paintable_snapshot(paint, s, width, height);
  GskRenderNode *node = gtk_snapshot_free_to_node(s);
  GskRenderer *renderer = gtk_native_get_renderer(GTK_NATIVE(w.window));
  if (node && renderer) {
    GdkTexture *t = gsk_renderer_render_texture(renderer, node, &GRAPHENE_RECT_INIT(0, 0, width, height));
    shot.ok = gdk_texture_save_to_png(t, shot.path);
    g_object_unref(t);
  }
  if (node) {
    gsk_render_node_unref(node);
  }
  g_object_unref(paint);
}

int credlock_window_snapshot(const credlock_view *v, const char *path, int dark) {
  if (!start()) {
    return -1;
  }
  adw_style_manager_set_color_scheme(adw_style_manager_get_default(),
                                     dark ? ADW_COLOR_SCHEME_FORCE_DARK : ADW_COLOR_SCHEME_FORCE_LIGHT);
  w.left = v->timeout > 0 ? v->timeout : 120;
  GtkWidget *root = build(v);
  w.window = make_window(root);
  arm(TRUE);
  shot.path = path;
  shot.done = FALSE;
  shot.ok = FALSE;
  gtk_window_present(GTK_WINDOW(w.window));
  GdkFrameClock *clock = gtk_widget_get_frame_clock(w.window);
  gulong id = g_signal_connect(clock, "after-paint", G_CALLBACK(after_paint),
                               adw_window_get_content(ADW_WINDOW(w.window)));
  gtk_widget_queue_draw(w.window);
  while (!shot.done) {
    g_main_context_iteration(NULL, TRUE);
  }
  g_signal_handler_disconnect(clock, id);
  gtk_window_destroy(GTK_WINDOW(w.window));
  while (g_main_context_iteration(NULL, FALSE)) {
  }
  return shot.ok ? 0 : -1;
}
