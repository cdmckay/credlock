// credlock's service worker: show each push as a notification, and open the
// web app where it points when the notification is tapped. Every push must
// show a notification: iOS ends a subscription that pushes silently.
"use strict";

self.addEventListener("push", (event) => {
  let d = { title: "credlock", body: "" };
  try {
    d = event.data ? event.data.json() : d;
  } catch (e) {
    d.body = event.data ? event.data.text() : "";
  }
  event.waitUntil(
    self.registration.showNotification(d.title || "credlock", {
      body: d.body || "",
      tag: d.tag || "credlock",
      data: { url: d.url || "/" },
      // Slice 1 checks whether iOS shows this button at all.
      actions: [{ action: "review", title: "Review" }],
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      for (const w of windows) {
        if ("navigate" in w) return w.navigate(url).then((c) => (c || w).focus());
      }
      return self.clients.openWindow(url);
    }),
  );
});
