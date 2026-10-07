package webpush

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8291 section 5's worked example, byte for byte.
func TestEncryptMatchesRFC8291sWorkedExample(t *testing.T) {
	var sub Subscription
	sub.Keys.P256dh = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	sub.Keys.Auth = "BTBZMqHH6r4Tts7J_aSIgg"
	sender, err := ecdh.P256().NewPrivateKey(mustDecode(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	salt := mustDecode(t, "DGv6ra1nlYgDCS1FRnbzlw")
	got, err := encrypt(sub, []byte("When I grow up, I want to be a watermelon"), salt, sender)
	if err != nil {
		t.Fatal(err)
	}
	want := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
		"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
		"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if b64.EncodeToString(got) != want {
		t.Fatalf("encrypted:\n got %s\nwant %s", b64.EncodeToString(got), want)
	}
}

func TestEachMessageGetsItsOwnSaltAndKey(t *testing.T) {
	ua, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sub Subscription
	sub.Keys.P256dh = b64.EncodeToString(ua.PublicKey().Bytes())
	sub.Keys.Auth = b64.EncodeToString(make([]byte, 16))
	a, err := Encrypt(sub, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(sub, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a[:16]) == string(b[:16]) || string(a[21:86]) == string(b[21:86]) {
		t.Fatal("two messages shared a salt or a sender key")
	}
}

func TestATooLongMessageIsRefused(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	var sub Subscription
	sub.Keys.P256dh = b64.EncodeToString(ua.PublicKey().Bytes())
	sub.Keys.Auth = b64.EncodeToString(make([]byte, 16))
	if _, err := Encrypt(sub, make([]byte, recordSize)); err == nil {
		t.Fatal("a message longer than one record was encrypted")
	}
}

func TestSendPostsAnEncryptedMessageSignedForThePushService(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var got *http.Request
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	client = srv.Client()

	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	sub := Subscription{Endpoint: srv.URL + "/push/abc"}
	sub.Keys.P256dh = b64.EncodeToString(ua.PublicKey().Bytes())
	sub.Keys.Auth = b64.EncodeToString(make([]byte, 16))
	err = Send(context.Background(), k, sub, []byte("hi"), Options{TTL: 5 * time.Minute, Urgency: "high", Subject: "https://example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Content-Encoding") != "aes128gcm" || got.Header.Get("TTL") != "300" || got.Header.Get("Urgency") != "high" {
		t.Fatalf("headers: %v", got.Header)
	}
	if strings.Contains(string(body), "hi") && len(body) < 100 {
		t.Fatal("the body looks unencrypted")
	}

	// The Authorization header carries a JWT the push service can check with
	// the key the browser subscribed with.
	auth := got.Header.Get("Authorization")
	tok, pub, ok := strings.Cut(strings.TrimPrefix(auth, "vapid t="), ", k=")
	if !ok || pub != k.Public() {
		t.Fatalf("authorization: %q", auth)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt: %q", tok)
	}
	var claims struct {
		Aud string
		Exp int64
		Sub string
	}
	if err := json.Unmarshal(mustDecode(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != srv.URL || claims.Sub != "https://example.org" || claims.Exp <= time.Now().Unix() {
		t.Fatalf("claims: %+v", claims)
	}
	sig := mustDecode(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&k.priv.PublicKey, digest[:], r, s) {
		t.Fatal("the JWT's signature doesn't verify with the VAPID key")
	}
}

func TestAGoneSubscriptionSaysItExpired(t *testing.T) {
	k, _ := NewKey()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()
	client = srv.Client()
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	sub := Subscription{Endpoint: srv.URL + "/push/abc"}
	sub.Keys.P256dh = b64.EncodeToString(ua.PublicKey().Bytes())
	sub.Keys.Auth = b64.EncodeToString(make([]byte, 16))
	err := Send(context.Background(), k, sub, nil, Options{TTL: time.Minute, Subject: "https://example.org"})
	if err == nil || !strings.Contains(err.Error(), ErrExpired.Error()) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAKeySurvivesSavingAndLoading(t *testing.T) {
	k, _ := NewKey()
	der, err := k.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Public() != k.Public() {
		t.Fatal("the loaded key differs")
	}
}
