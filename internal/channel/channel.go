// Package channel is the connection between another machine and a hub: TLS
// 1.3, with each side proving itself with its own credlock key, in a
// certificate it signs itself. No certificate authority is involved. The hub
// learns the machine's key from its certificate, and the machine checks the
// hub's against the key it remembered when it paired. TLS ties both keys to
// the connection and encrypts it, so whatever relays it can neither read it
// nor answer in it.
package channel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/cdmckay/credlock/internal/state"
)

// Certificate is key in a certificate signed by itself, for TLS. Nothing
// checks its name or dates: only the key in it counts.
func Certificate(key ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "credlock"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// Server is the hub's side of conn. It requires the machine's certificate,
// whoever signed it: the key in it is who the machine is. Every connection is
// a full handshake, with no sessions to resume.
func Server(conn net.Conn, cert tls.Certificate) *tls.Conn {
	return tls.Server(conn, &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	})
}

// Client is the other machine's side of conn. check sees the hub's key during
// the handshake, before anything is sent, and refuses it by returning an
// error.
func Client(conn net.Conn, cert tls.Certificate, check func(hubKey string) error) *tls.Conn {
	return tls.Client(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// No certificate authority vouches for a hub: check compares its key
		// with the one this machine paired with.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			key, err := PeerKey(cs)
			if err != nil {
				return err
			}
			return check(key)
		},
	})
}

// PeerKey is the key in the other side's certificate, as state.PublicKey
// writes keys.
func PeerKey(cs tls.ConnectionState) (string, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("the other side sent no certificate")
	}
	pub, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("the other side's certificate doesn't hold an ed25519 key")
	}
	return state.EncodeKey(pub), nil
}

// PairingCode is the four digits both ends show for one pairing. It comes
// from the TLS session itself, so the two match only when both ends share
// it: anything that sits in the middle, with a session to each, shows each a
// different code.
func PairingCode(cs tls.ConnectionState) (string, error) {
	b, err := cs.ExportKeyingMaterial("credlock pairing code v1", nil, 4)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04d", binary.BigEndian.Uint32(b)%10000), nil
}
