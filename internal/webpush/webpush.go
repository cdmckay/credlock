// Package webpush sends Web Push messages (RFC 8030) to a browser's push
// subscription, encrypted end to end (RFC 8291) so the push service carrying
// them can't read them, and signed with the sender's VAPID key (RFC 8292) so
// the push service knows they come from the subscription's owner. It uses
// only Go's standard library.
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Subscription is what the browser's PushManager.subscribe() returns, as
// its toJSON() serializes it.
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"` // the browser's ECDH public key, uncompressed
		Auth   string `json:"auth"`   // a 16-byte secret shared with the browser
	} `json:"keys"`
}

// Key is the sender's VAPID key: an ECDSA P-256 key that the browser was
// given when it subscribed, and that signs every push sent to it.
type Key struct {
	priv *ecdsa.PrivateKey
}

// NewKey makes a VAPID key.
func NewKey() (Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, err
	}
	return Key{priv}, nil
}

// ParseKey reads a key saved by Key.Marshal.
func ParseKey(der []byte) (Key, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return Key{}, err
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return Key{}, errors.New("a VAPID key must be ECDSA P-256")
	}
	return Key{priv}, nil
}

// Marshal saves the private key, PKCS #8 DER.
func (k Key) Marshal() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k.priv) }

// Public is the key the browser's subscribe() takes as applicationServerKey:
// the uncompressed point, base64url.
func (k Key) Public() string {
	pub, err := k.priv.PublicKey.ECDH()
	if err != nil {
		panic(err) // a P-256 ECDSA key always converts
	}
	return b64.EncodeToString(pub.Bytes())
}

var b64 = base64.RawURLEncoding

// decode accepts base64url with or without padding, as browsers send both.
func decode(s string) ([]byte, error) {
	for len(s)%4 != 0 {
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// recordSize is the RFC 8188 record size declared in the header. A push
// message is one record, so it only has to exceed the message.
const recordSize = 4096

// Encrypt encrypts plaintext for sub as RFC 8291's aes128gcm content coding:
// a header naming the salt and the sender's one-time ECDH key, then a single
// AES-128-GCM record.
func Encrypt(sub Subscription, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypt(sub, plaintext, salt, eph)
}

// encrypt is Encrypt with the salt and the sender's key given, as RFC 8291's
// worked example needs.
func encrypt(sub Subscription, plaintext, salt []byte, eph *ecdh.PrivateKey) ([]byte, error) {
	uaPublic, err := decode(sub.Keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("subscription's p256dh: %w", err)
	}
	authSecret, err := decode(sub.Keys.Auth)
	if err != nil {
		return nil, fmt.Errorf("subscription's auth: %w", err)
	}
	if len(authSecret) != 16 {
		return nil, fmt.Errorf("subscription's auth is %d bytes, not 16", len(authSecret))
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, fmt.Errorf("subscription's p256dh: %w", err)
	}
	if plaintext == nil {
		plaintext = []byte{}
	}
	// One record holds the message, its delimiter and GCM's 16-byte tag.
	if len(plaintext)+1+16 > recordSize {
		return nil, fmt.Errorf("a push message can be %d bytes at most", recordSize-17)
	}
	secret, err := eph.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := eph.PublicKey().Bytes()

	// RFC 8291 section 3.4: the auth secret and both public keys go into
	// the input keying material, so only this browser can decrypt it.
	keyInfo := append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...)
	ikm, err := hkdf.Key(sha256.New, secret, authSecret, string(keyInfo), 32)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// RFC 8188 header: salt, record size, then the sender's public key as
	// the key ID. 0x02 marks the last (and only) record.
	var out bytes.Buffer
	out.Write(salt)
	_ = binary.Write(&out, binary.BigEndian, uint32(recordSize))
	out.WriteByte(byte(len(asPublic)))
	out.Write(asPublic)
	out.Write(gcm.Seal(nil, nonce, append(plaintext, 0x02), nil))
	return out.Bytes(), nil
}

// Options shape one push.
type Options struct {
	// TTL is how long the push service keeps a message the device can't
	// take yet. Past it, the message is dropped.
	TTL time.Duration
	// Urgency is the RFC 8030 urgency: "very-low", "low", "normal" or
	// "high". Empty means "normal".
	Urgency string
	// Subject is the VAPID "sub" claim: a mailto: or https: URL the push
	// service can contact about this sender.
	Subject string
}

// client is the push service client: every call has a deadline, so a slow
// push service never holds up whoever sends.
var client = &http.Client{Timeout: 15 * time.Second}

// Send encrypts payload for sub and posts it to sub's push service, signed
// with k. A push service answers 201 when it has the message.
func Send(ctx context.Context, k Key, sub Subscription, payload []byte, o Options) error {
	endpoint, err := url.Parse(sub.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("the subscription's endpoint isn't an https URL: %q", sub.Endpoint)
	}
	body, err := Encrypt(sub, payload)
	if err != nil {
		return err
	}
	jwt, err := k.vapid(endpoint.Scheme+"://"+endpoint.Host, o.Subject, time.Now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", strconv.Itoa(int(o.TTL/time.Second)))
	if o.Urgency != "" {
		req.Header.Set("Urgency", o.Urgency)
	}
	req.Header.Set("Authorization", "vapid t="+jwt+", k="+k.Public())
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return fmt.Errorf("%w: %s %s", ErrExpired, resp.Status, bytes.TrimSpace(msg))
	}
	return fmt.Errorf("push service answered %s: %s", resp.Status, bytes.TrimSpace(msg))
}

// ErrExpired is a subscription the push service no longer knows: the device
// has to subscribe again.
var ErrExpired = errors.New("the push subscription has expired")

// vapid is the RFC 8292 JWT for audience: ES256, valid for twelve hours.
func (k Key) vapid(audience, subject string, now time.Time) (string, error) {
	header := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(map[string]any{
		"aud": audience,
		"exp": now.Add(12 * time.Hour).Unix(),
		"sub": subject,
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return "", err
	}
	// JWS wants r and s as two fixed 32-byte integers, not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}
