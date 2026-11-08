package mimic

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
)

// Channel-bound token authentication used inside the TLS mimic. TLS provides the
// (single) crypto layer; this proves both peers know the pre-shared token AND are
// talking over the *same* TLS certificate, without ever sending the token.
//
// A MITM presenting its own cert makes the client's HMAC bind to the MITM cert;
// the real server verifies against its own cert -> mismatch -> reject. The MITM
// sees only HMACs (not the token) and cannot forge the server ack (no token). So
// possession of the public cert grants no ability to forge or inject.
//
//	client -> server:  MAGIC(8) ‖ nonce(16) ‖ HMAC(token, certFP ‖ nonce ‖ "C")(32)
//	server -> client:                          HMAC(token, certFP ‖ nonce ‖ "S")(32)
const (
	tlsAuthMagic = "HEDIOTLS"
	tlsNonceLen  = 16
	tlsMACLen    = 32
)

func tlsAuthMAC(token string, certFP [32]byte, nonce []byte, dir byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write(certFP[:])
	h.Write(nonce)
	h.Write([]byte{dir})
	return h.Sum(nil)
}

// clientProveTLS runs the client side over an established TLS conn: send the
// channel-bound auth and verify the server's ack.
func clientProveTLS(inner net.Conn, token string, certFP [32]byte) error {
	nonce := make([]byte, tlsNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	msg := make([]byte, 0, len(tlsAuthMagic)+tlsNonceLen+tlsMACLen)
	msg = append(msg, tlsAuthMagic...)
	msg = append(msg, nonce...)
	msg = append(msg, tlsAuthMAC(token, certFP, nonce, 'C')...)
	if _, err := inner.Write(msg); err != nil {
		return err
	}

	ack := make([]byte, tlsMACLen)
	if _, err := io.ReadFull(inner, ack); err != nil {
		return err
	}
	if !hmac.Equal(ack, tlsAuthMAC(token, certFP, nonce, 'S')) {
		return securestream.ErrAuth
	}
	return nil
}

// serverVerifyTLS runs the server side: read + verify the client's auth from r
// (a recorder over the TLS conn, so a non-client's bytes can be replayed to the
// web decoy), then write the ack to w. Returns securestream.ErrAuth on any
// failure. filter rejects replayed nonces (may be nil).
func serverVerifyTLS(w io.Writer, r io.Reader, token string, certFP [32]byte, filter *securestream.ReplayFilter) error {
	_, err := serverVerifyTLSAny(w, r, []string{token}, certFP, filter)
	return err
}

// serverVerifyTLSAny is serverVerifyTLS for a listener that serves several tokens
// (the hub's shared reverse listener: one SNI, several foreign nodes). The client's
// message is read once and checked against every token; the ack is written with the
// one that matched, whose index is returned. Every token is always checked, so the
// time taken does not reveal which one matched.
func serverVerifyTLSAny(w io.Writer, r io.Reader, tokens []string, certFP [32]byte, filter *securestream.ReplayFilter) (int, error) {
	magic := make([]byte, len(tlsAuthMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return -1, securestream.ErrAuth
	}
	if !bytes.Equal(magic, []byte(tlsAuthMagic)) {
		return -1, securestream.ErrAuth // not our client (e.g. a browser sending HTTP) -> decoy
	}
	body := make([]byte, tlsNonceLen+tlsMACLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return -1, securestream.ErrAuth
	}
	nonce, mac := body[:tlsNonceLen], body[tlsNonceLen:]
	matched := -1
	for i, token := range tokens {
		if token == "" {
			continue
		}
		if hmac.Equal(mac, tlsAuthMAC(token, certFP, nonce, 'C')) && matched < 0 {
			matched = i
		}
	}
	if matched < 0 {
		return -1, securestream.ErrAuth // wrong token or MITM (cert fingerprint differs)
	}
	if filter != nil && !filter.Accept(nonce) {
		return -1, securestream.ErrAuth // replayed handshake
	}
	if _, err := w.Write(tlsAuthMAC(tokens[matched], certFP, nonce, 'S')); err != nil {
		return -1, err
	}
	return matched, nil
}
