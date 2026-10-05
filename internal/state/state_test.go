package state

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolated(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	t.Setenv("CREDLOCK_STATE", dir)
	return dir
}

func TestTheKeyIsMadeOnceAndOnlyItsOwnerCanReadIt(t *testing.T) {
	dir := isolated(t)
	first, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Key()
	if err != nil || !first.Equal(again) {
		t.Fatalf("a second Key() gave another key: %v", err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "key"): 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %o (%v)", path, fi.Mode().Perm(), want, err)
		}
	}
}

func TestAKeyOthersCanReadIsRefused(t *testing.T) {
	dir := isolated(t)
	if _, err := Key(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Key(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
}

func TestPublicKeysRoundTripAndSign(t *testing.T) {
	isolated(t)
	priv, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(PublicKey(priv))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("challenge"), ed25519.Sign(priv, []byte("challenge"))) {
		t.Fatal("a signature didn't verify with the parsed key")
	}
	for _, bad := range []string{"", "ed25519:", "ed25519:not-base64!", "rsa:AAAA"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted it", bad)
		}
	}
}

func TestThePairingCodeIsFourDigitsBothSidesAgreeOn(t *testing.T) {
	c, n := []byte("challenge"), []byte("nonce")
	a := PairingCode(c, n, "ed25519:AAAA", "ed25519:HHHH")
	if len(a) != 4 || strings.Trim(a, "0123456789") != "" || a != PairingCode(c, n, "ed25519:AAAA", "ed25519:HHHH") {
		t.Fatalf("got %q", a)
	}
	if a == PairingCode([]byte("another"), n, "ed25519:AAAA", "ed25519:HHHH") &&
		a == PairingCode(c, []byte("other"), "ed25519:AAAA", "ed25519:HHHH") &&
		a == PairingCode(c, n, "ed25519:BBBB", "ed25519:HHHH") &&
		a == PairingCode(c, n, "ed25519:AAAA", "ed25519:IIII") {
		t.Fatal("the code ignores its inputs")
	}
}

func TestTheTwoProofsCanNeverBeEachOther(t *testing.T) {
	a, b := []byte("aaaa"), []byte("bbbb")
	if string(HubProof(a, b)) == string(ClientProof(a, b, "")) || string(HubProof(a, b)) == string(HubProof(b, a)) {
		t.Fatal("a proof can pass for another")
	}
	// Lengths are part of the message, so moving bytes between parts changes it.
	if string(ClientProof([]byte("ab"), []byte("c"), "k")) == string(ClientProof([]byte("a"), []byte("bc"), "k")) {
		t.Fatal("parts can shift into each other")
	}
}

func TestHubAndClientStateRoundTrip(t *testing.T) {
	isolated(t)
	h := Hub{Enabled: true, Tailnet: "example.org", Peers: map[string]Peer{
		PeerID("me", "papaya"): {Host: "papaya", User: "me", Key: "ed25519:AAAA", PairedAt: time.Unix(0, 0).UTC()},
	}}
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHub()
	if err != nil || !got.Enabled || got.Tailnet != "example.org" || got.Peers["me@papaya"].Key != "ed25519:AAAA" {
		t.Fatalf("%+v, %v", got, err)
	}
	var c Client
	if !c.Remember("potato", "ed25519:HHHH") || c.Remember("Potato", "ed25519:HHHH") {
		t.Fatal("Remember should add a hub once, whatever its case")
	}
	if !c.Remember("potato", "ed25519:IIII") || len(c.Hubs) != 1 {
		t.Fatalf("pairing again with a new key should replace the key: %+v", c)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadClient(); err != nil || len(got.Hubs) != 1 || got.Keys["potato"] != "ed25519:IIII" {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestNothingSavedIsEmpty(t *testing.T) {
	isolated(t)
	if h, err := LoadHub(); err != nil || h.Enabled || len(h.Peers) != 0 {
		t.Fatalf("%+v, %v", h, err)
	}
	if c, err := LoadClient(); err != nil || len(c.Hubs) != 0 {
		t.Fatalf("%+v, %v", c, err)
	}
}
