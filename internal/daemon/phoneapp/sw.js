// credlock's service worker: show each push as a notification, and bring
// the web app forward when one is tapped. The app then asks the hub what is
// waiting, so nothing here needs to reach the page. Every push must show a
// notification: iOS ends a subscription that pushes silently.
"use strict";

// A new version of this worker takes over at once, not once the app has
// been closed.
self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("push", (event) => {
  let d = { title: "credlock", body: "" };
  try {
    d = event.data ? event.data.json() : d;
  } catch (e) {
    d.body = event.data ? event.data.text() : "";
  }
  // No action buttons: iOS doesn't show them, so a tap opens the app.
  event.waitUntil(
    self.registration.showNotification(d.title || "credlock", {
      body: d.body || "",
      tag: d.tag || "credlock",
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(open());
});

// open brings the app forward. iOS does this itself on a tap, opening the
// app if it was closed; other browsers need the worker to. The report comes
// after: the tap's gesture doesn't outlast a network round trip, and iOS
// refuses openWindow without it.
async function open() {
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const how = windows.length > 0 ? "focus" : "openWindow";
  try {
    if (windows.length > 0) await windows[0].focus();
    else await self.clients.openWindow("/");
    await report({ notificationclick: how });
  } catch (e) {
    await report({ notificationclick: how, error: String(e) });
  }
}

// report tells the hub what happened here, which nothing else can see.
function report(event) {
  return fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  }).catch(() => {});
}
