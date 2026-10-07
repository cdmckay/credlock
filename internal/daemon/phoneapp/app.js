// credlock's phone web app, slice 1 of #14: subscribe this phone to push
// notifications from its hub, and show what a notification carried.
"use strict";

const $ = (id) => document.getElementById(id);
const log = (m) => { $("log").textContent += m + "\n"; };
const standalone =
  window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;

async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
  return r;
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

// What this browser supports, reported to the hub so slice 1's open
// questions are answered by the phone itself.
async function capabilities() {
  const c = {
    standalone,
    serviceWorker: "serviceWorker" in navigator,
    pushManager: "PushManager" in window,
    notification: "Notification" in window ? Notification.permission : "unsupported",
    notificationMaxActions:
      "Notification" in window && "maxActions" in Notification ? Notification.maxActions : null,
    webauthn: "PublicKeyCredential" in window,
    platformAuthenticator: false,
    getPublicKey:
      typeof AuthenticatorAttestationResponse !== "undefined" &&
      "getPublicKey" in AuthenticatorAttestationResponse.prototype,
    userAgent: navigator.userAgent,
  };
  try {
    c.platformAuthenticator =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (e) {
    // no WebAuthn
  }
  return c;
}

async function main() {
  const caps = await capabilities();
  post("/api/caps", caps).catch((e) => log(e.message));
  $("where").textContent = standalone ? "Opened from the Home Screen." : "Opened in the browser.";

  const n = new URLSearchParams(location.search).get("n");
  if (n) {
    const r = await fetch("/api/message?n=" + encodeURIComponent(n));
    $("msg").textContent = r.ok ? await r.text() : "That notification has expired.";
    $("message").hidden = false;
  }

  if (!caps.serviceWorker || !caps.pushManager) {
    // On iOS, Web Push exists only for web apps opened from the Home Screen.
    if (standalone) log("This browser can't receive push notifications.");
    else $("install").hidden = false;
    return;
  }
  const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  if (sub && Notification.permission === "granted") {
    await post("/api/subscribe", sub.toJSON());
    $("ready").hidden = false;
  } else {
    $("enable").hidden = false;
  }
}

$("subscribe").onclick = async () => {
  try {
    // iOS asks for permission only from a tap like this one.
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      log("Notifications weren't allowed (" + permission + ").");
      return;
    }
    const { key } = await (await fetch("/api/vapid")).json();
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64urlToBytes(key),
    });
    await post("/api/subscribe", sub.toJSON());
    $("enable").hidden = true;
    $("ready").hidden = false;
  } catch (e) {
    log(e.message);
  }
};

$("test").onclick = async () => {
  try {
    await post("/api/test", {});
    log("Sent. It should arrive within a few seconds.");
  } catch (e) {
    log(e.message);
  }
};

main().catch((e) => log(e.message));
