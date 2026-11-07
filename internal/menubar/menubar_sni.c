//go:build linux && gtk

// The tray icon on Linux: a StatusNotifierItem, the D-Bus protocol that KDE,
// most other desktops and GNOME's AppIndicator extension show in their
// panels, with its menu as a com.canonical.dbusmenu. GIO speaks D-Bus here,
// as GLib is already the window's. menubar_sni.go builds the menu and the
// icon's state from the helper's snapshots; this only serves them, and hands
// back the ids of clicked items, which Go turns into actions that can only
// take access away.

#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "_cgo_export.h"
#include "menubar_sni.h"

#define ITEM_PATH "/StatusNotifierItem"
#define ITEM_IFACE "org.kde.StatusNotifierItem"
#define MENU_PATH "/MenuBar"
#define MENU_IFACE "com.canonical.dbusmenu"
#define WATCHER "org.kde.StatusNotifierWatcher"

static const char *kItemXML =
    "<node><interface name='" ITEM_IFACE "'>"
    "<property name='Category' type='s' access='read'/>"
    "<property name='Id' type='s' access='read'/>"
    "<property name='Title' type='s' access='read'/>"
    "<property name='Status' type='s' access='read'/>"
    "<property name='WindowId' type='i' access='read'/>"
    "<property name='IconThemePath' type='s' access='read'/>"
    "<property name='IconName' type='s' access='read'/>"
    "<property name='IconPixmap' type='a(iiay)' access='read'/>"
    "<property name='OverlayIconName' type='s' access='read'/>"
    "<property name='OverlayIconPixmap' type='a(iiay)' access='read'/>"
    "<property name='AttentionIconName' type='s' access='read'/>"
    "<property name='AttentionIconPixmap' type='a(iiay)' access='read'/>"
    "<property name='AttentionMovieName' type='s' access='read'/>"
    "<property name='ToolTip' type='(sa(iiay)ss)' access='read'/>"
    "<property name='ItemIsMenu' type='b' access='read'/>"
    "<property name='Menu' type='o' access='read'/>"
    "<property name='XAyatanaLabel' type='s' access='read'/>"
    "<property name='XAyatanaLabelGuide' type='s' access='read'/>"
    "<property name='XAyatanaOrderingIndex' type='u' access='read'/>"
    "<method name='ContextMenu'><arg type='i' direction='in'/><arg type='i' direction='in'/></method>"
    "<method name='Activate'><arg type='i' direction='in'/><arg type='i' direction='in'/></method>"
    "<method name='SecondaryActivate'><arg type='i' direction='in'/><arg type='i' direction='in'/></method>"
    "<method name='Scroll'><arg type='i' direction='in'/><arg type='s' direction='in'/></method>"
    "<signal name='NewTitle'/><signal name='NewIcon'/><signal name='NewAttentionIcon'/>"
    "<signal name='NewOverlayIcon'/><signal name='NewToolTip'/>"
    "<signal name='NewStatus'><arg type='s'/></signal>"
    "<signal name='XAyatanaNewLabel'><arg type='s'/><arg type='s'/></signal>"
    "</interface></node>";

static const char *kMenuXML =
    "<node><interface name='" MENU_IFACE "'>"
    "<property name='Version' type='u' access='read'/>"
    "<property name='TextDirection' type='s' access='read'/>"
    "<property name='Status' type='s' access='read'/>"
    "<property name='IconThemePath' type='as' access='read'/>"
    "<method name='GetLayout'><arg type='i' direction='in'/><arg type='i' direction='in'/>"
    "<arg type='as' direction='in'/><arg type='u' direction='out'/><arg type='(ia{sv}av)' direction='out'/></method>"
    "<method name='GetGroupProperties'><arg type='ai' direction='in'/><arg type='as' direction='in'/>"
    "<arg type='a(ia{sv})' direction='out'/></method>"
    "<method name='GetProperty'><arg type='i' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='v' direction='out'/></method>"
    "<method name='Event'><arg type='i' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='v' direction='in'/><arg type='u' direction='in'/></method>"
    "<method name='EventGroup'><arg type='a(isvu)' direction='in'/><arg type='ai' direction='out'/></method>"
    "<method name='AboutToShow'><arg type='i' direction='in'/><arg type='b' direction='out'/></method>"
    "<method name='AboutToShowGroup'><arg type='ai' direction='in'/><arg type='ai' direction='out'/>"
    "<arg type='ai' direction='out'/></method>"
    "<signal name='ItemsPropertiesUpdated'><arg type='a(ia{sv})'/><arg type='a(ias)'/></signal>"
    "<signal name='LayoutUpdated'><arg type='u'/><arg type='i'/></signal>"
    "<signal name='ItemActivationRequested'><arg type='i'/><arg type='u'/></signal>"
    "</interface></node>";

// What the tray shows. Only the main loop's thread touches it.
static struct {
  GMainLoop *loop;
  gboolean quit;  // asked to quit before the loop ran
  GDBusConnection *bus;
  char *name;  // the bus name the item is registered under
  char *icon_dir;
  char *icon;
  char *label;
  char *tooltip;
  gboolean active;
  GVariant *layout;
  guint32 revision;
} t;

static GVariant *empty_layout(void) {
  return g_variant_ref_sink(g_variant_parse(G_VARIANT_TYPE("(ia{sv}av)"), "(0, {}, [])", NULL, NULL, NULL));
}

static GVariant *no_pixmaps(void) { return g_variant_new_array(G_VARIANT_TYPE("(iiay)"), NULL, 0); }

static void emit(const char *path, const char *iface, const char *signal, GVariant *args) {
  if (t.bus) {
    g_dbus_connection_emit_signal(t.bus, NULL, path, iface, signal, args, NULL);
  } else if (args) {
    g_variant_unref(g_variant_ref_sink(args));
  }
}

// The menu.

// find is the item id in node, or NULL.
static GVariant *find(GVariant *node, gint32 id) {
  gint32 here;
  g_variant_get_child(node, 0, "i", &here);
  if (here == id) {
    return g_variant_ref(node);
  }
  GVariant *children = g_variant_get_child_value(node, 2);
  GVariant *found = NULL;
  for (gsize i = 0; !found && i < g_variant_n_children(children); i++) {
    GVariant *boxed = g_variant_get_child_value(children, i);
    GVariant *child = g_variant_get_variant(boxed);
    found = find(child, id);
    g_variant_unref(child);
    g_variant_unref(boxed);
  }
  g_variant_unref(children);
  return found;
}

// trim is node with its children only depth levels down; -1 is all of them.
static GVariant *trim(GVariant *node, gint32 depth) {
  if (depth < 0) {
    return g_variant_ref(node);
  }
  gint32 id;
  GVariant *props;
  g_variant_get_child(node, 0, "i", &id);
  props = g_variant_get_child_value(node, 1);
  GVariantBuilder kids;
  g_variant_builder_init(&kids, G_VARIANT_TYPE("av"));
  if (depth > 0) {
    GVariant *children = g_variant_get_child_value(node, 2);
    for (gsize i = 0; i < g_variant_n_children(children); i++) {
      GVariant *boxed = g_variant_get_child_value(children, i);
      GVariant *child = g_variant_get_variant(boxed);
      GVariant *trimmed = trim(child, depth - 1);
      g_variant_builder_add(&kids, "v", trimmed);
      g_variant_unref(trimmed);
      g_variant_unref(child);
      g_variant_unref(boxed);
    }
    g_variant_unref(children);
  }
  GVariant *out = g_variant_new("(i@a{sv}av)", id, props, &kids);
  g_variant_unref(props);
  return g_variant_ref_sink(out);
}

static void clicked(gint32 id, const char *event) {
  if (strcmp(event, "clicked") == 0) {
    credlockTrayEvent(id);
  }
}

static void menu_call(GDBusConnection *c, const char *sender, const char *path, const char *iface, const char *method,
                      GVariant *args, GDBusMethodInvocation *inv, gpointer data) {
  if (strcmp(method, "GetLayout") == 0) {
    gint32 parent, depth;
    g_variant_get(args, "(ii@as)", &parent, &depth, NULL);
    GVariant *node = find(t.layout, parent);
    if (!node) {
      g_dbus_method_invocation_return_dbus_error(inv, "com.canonical.dbusmenu.Error", "no such item");
      return;
    }
    GVariant *out = trim(node, depth);
    g_dbus_method_invocation_return_value(inv, g_variant_new("(u@(ia{sv}av))", t.revision, out));
    g_variant_unref(out);
    g_variant_unref(node);
  } else if (strcmp(method, "GetGroupProperties") == 0) {
    GVariantIter *ids;
    gint32 id;
    g_variant_get(args, "(aias)", &ids, NULL);
    GVariantBuilder out;
    g_variant_builder_init(&out, G_VARIANT_TYPE("a(ia{sv})"));
    while (g_variant_iter_next(ids, "i", &id)) {
      GVariant *node = find(t.layout, id);
      if (node) {
        GVariant *props = g_variant_get_child_value(node, 1);
        g_variant_builder_add(&out, "(i@a{sv})", id, props);
        g_variant_unref(props);
        g_variant_unref(node);
      }
    }
    g_variant_iter_free(ids);
    g_dbus_method_invocation_return_value(inv, g_variant_new("(a(ia{sv}))", &out));
  } else if (strcmp(method, "GetProperty") == 0) {
    gint32 id;
    const char *name;
    g_variant_get(args, "(i&s)", &id, &name);
    GVariant *node = find(t.layout, id);
    GVariant *value = NULL;
    if (node) {
      GVariant *props = g_variant_get_child_value(node, 1);
      value = g_variant_lookup_value(props, name, NULL);
      g_variant_unref(props);
      g_variant_unref(node);
    }
    if (!value) {
      g_dbus_method_invocation_return_dbus_error(inv, "com.canonical.dbusmenu.Error", "no such property");
      return;
    }
    g_dbus_method_invocation_return_value(inv, g_variant_new("(v)", value));
    g_variant_unref(value);
  } else if (strcmp(method, "Event") == 0) {
    gint32 id;
    const char *event;
    g_variant_get(args, "(i&svu)", &id, &event, NULL, NULL);
    g_dbus_method_invocation_return_value(inv, NULL);
    clicked(id, event);
  } else if (strcmp(method, "EventGroup") == 0) {
    GVariantIter *events;
    gint32 id;
    const char *event;
    g_variant_get(args, "(a(isvu))", &events);
    g_dbus_method_invocation_return_value(inv, g_variant_new("(@ai)", g_variant_new_array(G_VARIANT_TYPE_INT32, NULL, 0)));
    while (g_variant_iter_next(events, "(i&svu)", &id, &event, NULL, NULL)) {
      clicked(id, event);
    }
    g_variant_iter_free(events);
  } else if (strcmp(method, "AboutToShow") == 0) {
    g_dbus_method_invocation_return_value(inv, g_variant_new("(b)", FALSE));
  } else if (strcmp(method, "AboutToShowGroup") == 0) {
    g_dbus_method_invocation_return_value(
        inv, g_variant_new("(@ai@ai)", g_variant_new_array(G_VARIANT_TYPE_INT32, NULL, 0),
                           g_variant_new_array(G_VARIANT_TYPE_INT32, NULL, 0)));
  } else {
    g_dbus_method_invocation_return_dbus_error(inv, "org.freedesktop.DBus.Error.UnknownMethod", method);
  }
}

static GVariant *menu_get(GDBusConnection *c, const char *sender, const char *path, const char *iface,
                          const char *prop, GError **err, gpointer data) {
  if (strcmp(prop, "Version") == 0) {
    return g_variant_new_uint32(3);
  }
  if (strcmp(prop, "TextDirection") == 0) {
    return g_variant_new_string("ltr");
  }
  if (strcmp(prop, "Status") == 0) {
    return g_variant_new_string("normal");
  }
  if (strcmp(prop, "IconThemePath") == 0) {
    const char *dirs[] = {t.icon_dir, NULL};
    return g_variant_new_strv(dirs, -1);
  }
  return NULL;
}

// The icon.

static void item_call(GDBusConnection *c, const char *sender, const char *path, const char *iface, const char *method,
                      GVariant *args, GDBusMethodInvocation *inv, gpointer data) {
  // Activating the icon does nothing beyond the menu it opens.
  g_dbus_method_invocation_return_value(inv, NULL);
}

static GVariant *item_get(GDBusConnection *c, const char *sender, const char *path, const char *iface,
                          const char *prop, GError **err, gpointer data) {
  if (strcmp(prop, "Category") == 0) {
    return g_variant_new_string("ApplicationStatus");
  }
  if (strcmp(prop, "Id") == 0 || strcmp(prop, "Title") == 0) {
    return g_variant_new_string("credlock");
  }
  if (strcmp(prop, "Status") == 0) {
    return g_variant_new_string(t.active ? "Active" : "Passive");
  }
  if (strcmp(prop, "WindowId") == 0) {
    return g_variant_new_int32(0);
  }
  if (strcmp(prop, "IconThemePath") == 0) {
    return g_variant_new_string(t.icon_dir);
  }
  if (strcmp(prop, "IconName") == 0) {
    return g_variant_new_string(t.icon);
  }
  if (strcmp(prop, "OverlayIconName") == 0 || strcmp(prop, "AttentionIconName") == 0 ||
      strcmp(prop, "AttentionMovieName") == 0 || strcmp(prop, "XAyatanaLabelGuide") == 0) {
    return g_variant_new_string("");
  }
  if (strcmp(prop, "IconPixmap") == 0 || strcmp(prop, "OverlayIconPixmap") == 0 ||
      strcmp(prop, "AttentionIconPixmap") == 0) {
    return no_pixmaps();
  }
  if (strcmp(prop, "ToolTip") == 0) {
    return g_variant_new("(s@a(iiay)ss)", t.icon, no_pixmaps(), "credlock", t.tooltip);
  }
  if (strcmp(prop, "ItemIsMenu") == 0) {
    return g_variant_new_boolean(TRUE);
  }
  if (strcmp(prop, "Menu") == 0) {
    return g_variant_new_object_path(MENU_PATH);
  }
  if (strcmp(prop, "XAyatanaLabel") == 0) {
    return g_variant_new_string(t.label);
  }
  if (strcmp(prop, "XAyatanaOrderingIndex") == 0) {
    return g_variant_new_uint32(0);
  }
  return NULL;
}

// The panel that shows the icon.

// host_is_gnome says whether the panel is gnome-shell's: its AppIndicator
// extension reads underscores in labels unlike the dbusmenu spec. The bus,
// not the panel, says which process owns the name.
static gboolean host_is_gnome(const char *owner) {
  GVariant *r = g_dbus_connection_call_sync(t.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                            "org.freedesktop.DBus", "GetConnectionUnixProcessID",
                                            g_variant_new("(s)", owner), G_VARIANT_TYPE("(u)"),
                                            G_DBUS_CALL_FLAGS_NONE, 3000, NULL, NULL);
  if (!r) {
    return FALSE;
  }
  guint32 pid;
  g_variant_get(r, "(u)", &pid);
  g_variant_unref(r);
  char path[64], comm[64] = "";
  snprintf(path, sizeof path, "/proc/%u/comm", pid);
  FILE *f = fopen(path, "r");
  if (f) {
    if (!fgets(comm, sizeof comm, f)) {
      comm[0] = 0;
    }
    fclose(f);
  }
  // Contains, not equals: NixOS runs it as ".gnome-shell-wrapped", which
  // the kernel cuts to ".gnome-shell-wr".
  comm[strcspn(comm, "\n")] = 0;
  return strstr(comm, "gnome-shell") != NULL;
}

static void registered(GObject *src, GAsyncResult *res, gpointer data) {
  GVariant *r = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, NULL);
  if (r) {
    g_variant_unref(r);
  }
}

// A panel appeared, at start or later, as when its extension is turned on:
// say how it reads labels, and register with it.
static void watcher_appeared(GDBusConnection *c, const char *name, const char *owner, gpointer data) {
  credlockTrayHost(host_is_gnome(owner));
  g_dbus_connection_call(c, WATCHER, "/StatusNotifierWatcher", WATCHER, "RegisterStatusNotifierItem",
                         g_variant_new("(s)", t.name), NULL, G_DBUS_CALL_FLAGS_NONE, 3000, NULL, registered, NULL);
}

// Updates, from any thread.

typedef struct {
  char *layout, *icon, *label, *tooltip;
  gboolean active;
} update;

static gboolean apply(gpointer data) {
  update *u = data;
  GVariant *layout = g_variant_parse(G_VARIANT_TYPE("(ia{sv}av)"), u->layout, NULL, NULL, NULL);
  if (layout) {
    g_variant_unref(t.layout);
    t.layout = g_variant_ref_sink(layout);
    t.revision++;
    emit(MENU_PATH, MENU_IFACE, "LayoutUpdated", g_variant_new("(ui)", t.revision, 0));
  }
  gboolean was = t.active;
  g_free(t.icon);
  g_free(t.label);
  g_free(t.tooltip);
  t.icon = u->icon;
  t.label = u->label;
  t.tooltip = u->tooltip;
  t.active = u->active;
  emit(ITEM_PATH, ITEM_IFACE, "NewIcon", NULL);
  emit(ITEM_PATH, ITEM_IFACE, "NewToolTip", NULL);
  emit(ITEM_PATH, ITEM_IFACE, "XAyatanaNewLabel", g_variant_new("(ss)", t.label, ""));
  if (was != t.active) {
    emit(ITEM_PATH, ITEM_IFACE, "NewStatus", g_variant_new("(s)", t.active ? "Active" : "Passive"));
  }
  g_free(u->layout);
  g_free(u);
  return G_SOURCE_REMOVE;
}

void credlock_tray_update(const char *layout, const char *icon, const char *label, const char *tooltip,
                          int active) {
  update *u = g_new0(update, 1);
  u->layout = g_strdup(layout);
  u->icon = g_strdup(icon);
  u->label = g_strdup(label);
  u->tooltip = g_strdup(tooltip);
  u->active = active != 0;
  g_idle_add(apply, u);
}

static gboolean stop(gpointer data) {
  if (t.loop) {
    g_main_loop_quit(t.loop);
  } else {
    t.quit = TRUE;
  }
  return G_SOURCE_REMOVE;
}

void credlock_tray_quit(void) { g_idle_add(stop, NULL); }

int credlock_tray_layout_ok(const char *layout) {
  GVariant *v = g_variant_parse(G_VARIANT_TYPE("(ia{sv}av)"), layout, NULL, NULL, NULL);
  if (!v) {
    return 0;
  }
  g_variant_unref(g_variant_ref_sink(v));
  return 1;
}

int credlock_tray_run(const char *icon_dir) {
  t.icon_dir = g_strdup(icon_dir);
  t.icon = g_strdup("credlock-key-symbolic");
  t.label = g_strdup("");
  t.tooltip = g_strdup("credlock");
  t.layout = empty_layout();
  t.bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);
  if (!t.bus) {
    return 1;
  }
  static const GDBusInterfaceVTable item_vtable = {item_call, item_get, NULL};
  static const GDBusInterfaceVTable menu_vtable = {menu_call, menu_get, NULL};
  GDBusNodeInfo *item = g_dbus_node_info_new_for_xml(kItemXML, NULL);
  GDBusNodeInfo *menu = g_dbus_node_info_new_for_xml(kMenuXML, NULL);
  if (!item || !menu ||
      !g_dbus_connection_register_object(t.bus, ITEM_PATH, item->interfaces[0], &item_vtable, NULL, NULL, NULL) ||
      !g_dbus_connection_register_object(t.bus, MENU_PATH, menu->interfaces[0], &menu_vtable, NULL, NULL, NULL)) {
    return 1;
  }
  t.name = g_strdup_printf("org.kde.StatusNotifierItem-%d-1", (int)getpid());
  g_bus_own_name_on_connection(t.bus, t.name, G_BUS_NAME_OWNER_FLAGS_NONE, NULL, NULL, NULL, NULL);
  g_bus_watch_name_on_connection(t.bus, WATCHER, G_BUS_NAME_WATCHER_FLAGS_NONE, watcher_appeared, NULL, NULL,
                                 NULL);
  t.loop = g_main_loop_new(NULL, FALSE);
  if (!t.quit) {
    g_main_loop_run(t.loop);
  }
  return 0;
}
