// Package securestream implements Hedioum's authenticated, encrypted wire
// protocol. It replaces the old repeating-key XOR obfuscation and the
// cleartext-token handshake with a Shadowsocks-inspired AEAD stream:
//
//   - Per-connection, per-direction random salt sent in the clear.
//   - Subkey = HKDF-SHA256(pre-shared token, salt, info).
//   - ChaCha20-Poly1305 AEAD framing (no AES-NI required -> fast on cheap/ARM
//     VPS), with a per-direction incrementing nonce.
//   - Authentication is folded into the AEAD: the client's first frame carries a
//     magic marker; if its tag does not verify under the PSK-derived key, the
//     peer is not authentic and the caller can route it to the SSH decoy.
//   - Anti-replay uses a server-local TTL cache of client salts, so the two
//     nodes need no clock synchronization (no wall-clock timestamp is used).
//   - Each frame carries random trailing padding to vary on-wire sizes.
//
// The token is never transmitted. A passive on-path observer sees only random
// salts followed by AEAD ciphertext, and cannot recover the key or decrypt.
package securestream

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltSize  = 32
	keySize   = chacha20poly1305.KeySize // 32
	tagSize   = 16
	nonceSize = chacha20poly1305.NonceSize // 12
	maxChunk  = 0x3FFF                     // 16383 bytes of plaintext per AEAD chunk (Shadowsocks convention)
	maxPad    = 255                        // max random padding appended per frame (traffic-shape obfuscation)
	lenHdrLen = 4                          // encrypted length header: uint16 payloadLen + uint16 padLen
	magicSize = 8
	authPlain = magicSize // auth frame plaintext = magic only (no wall-clock timestamp)
	hkdfInfo  = "hedioum-aead-v1"

	hsDeadline = 10 * time.Second
)

var magic = [magicSize]byte{'H', 'E', 'D', 'I', 'O', 'U', 'M', '1'}

var (
	// ErrAuth signals the peer failed authentication. The egress caller uses this
	// to divert the (recorded) byte stream to the SSH decoy instead of banning.
	ErrAuth = errors.New("securestream: authentication failed")
)

// SecureConn is a net.Conn that transparently AEAD-encrypts writes and decrypts
// reads once the handshake has completed.
type SecureConn struct {
	net.Conn

	readMu   sync.Mutex
	rAEAD    cipher.AEAD
	rNonce   [nonceSize]byte
	leftover []byte // owned buffer holding decrypted-but-undelivered payload
	lenBuf   []byte // scratch for reading the encrypted length header
	payBuf   []byte // scratch for reading the encrypted payload block
	padBuf   []byte // scratch for discarding incoming random padding

	writeMu sync.Mutex
	wAEAD   cipher.AEAD
	wNonce  [nonceSize]byte
	frameBf []byte // scratch for building outbound frames
}

// deriveKey expands the pre-shared token into a 32-byte AEAD key for one
// direction, bound to that direction's random salt.
func deriveKey(psk, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, psk, salt, hkdfInfo, keySize)
}

func incrementNonce(n *[nonceSize]byte) {
	for i := 0; i < nonceSize; i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// ClientHandshake performs the client side of the upgrade over an already
// banner-exchanged connection: it sends its salt + an authentication frame,
// then reads the server's salt. token is the pre-shared secret (never sent).
func ClientHandshake(conn net.Conn, token string) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(hsDeadline))
	defer conn.SetDeadline(time.Time{})

	psk := []byte(token)

	// 1. Send our salt and derive the write key.
	saltC := make([]byte, saltSize)
	if _, err := rand.Read(saltC); err != nil {
		return nil, err
	}
	if _, err := conn.Write(saltC); err != nil {
		return nil, err
	}
	wKey, err := deriveKey(psk, saltC)
	if err != nil {
		return nil, err
	}
	wAEAD, err := chacha20poly1305.New(wKey)
	if err != nil {
		return nil, err
	}

	sc := newSecureConn(conn)
	sc.wAEAD = wAEAD

	// 2. Send the authentication frame: the magic marker, proven authentic by its
	// AEAD tag under the PSK-derived key. No wall-clock timestamp is used, so the
	// two nodes need no clock synchronization.
	if err := sc.writeChunk(magic[:]); err != nil {
		return nil, fmt.Errorf("send auth frame: %w", err)
	}

	// 3. Read the server salt and derive the read key.
	saltS := make([]byte, saltSize)
	if _, err := io.ReadFull(conn, saltS); err != nil {
		return nil, fmt.Errorf("read server salt: %w", err)
	}
	rKey, err := deriveKey(psk, saltS)
	if err != nil {
		return nil, err
	}
	rAEAD, err := chacha20poly1305.New(rKey)
	if err != nil {
		return nil, err
	}
	sc.rAEAD = rAEAD

	return sc, nil
}

// ServerHandshake performs the server side of the upgrade. It reads the client
// salt + auth frame; on any authentication failure it returns ErrAuth so the
// caller can divert to the decoy. filter may be nil to skip replay protection.
func ServerHandshake(conn net.Conn, token string, filter *ReplayFilter) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(hsDeadline))
	defer conn.SetDeadline(time.Time{})

	psk := []byte(token)

	// 1. Read the client salt and derive the read key.
	saltC := make([]byte, saltSize)
	if _, err := io.ReadFull(conn, saltC); err != nil {
		return nil, fmt.Errorf("read client salt: %w", err)
	}
	rKey, err := deriveKey(psk, saltC)
	if err != nil {
		return nil, err
	}
	rAEAD, err := chacha20poly1305.New(rKey)
	if err != nil {
		return nil, err
	}

	sc := newSecureConn(conn)
	sc.rAEAD = rAEAD

	// 2. Read + verify the authentication frame. A wrong PSK yields a wrong key
	// and the AEAD tag fails -> ErrAuth -> decoy.
	authPlaintext, err := sc.readChunk()
	if err != nil || len(authPlaintext) != authPlain {
		return nil, ErrAuth
	}
	if subtle.ConstantTimeCompare(authPlaintext, magic[:]) != 1 {
		return nil, ErrAuth
	}
	// 3. Anti-replay: reject a salt we have already accepted. The filter uses the
	// egress's own monotonic clock for its TTL, so no cross-node time sync (and no
	// external NTP) is required.
	if filter != nil && !filter.Accept(saltC) {
		return nil, ErrAuth
	}

	// 4. Authenticated. Send our salt and derive the write key.
	saltS := make([]byte, saltSize)
	if _, err := rand.Read(saltS); err != nil {
		return nil, err
	}
	if _, err := conn.Write(saltS); err != nil {
		return nil, err
	}
	wKey, err := deriveKey(psk, saltS)
	if err != nil {
		return nil, err
	}
	wAEAD, err := chacha20poly1305.New(wKey)
	if err != nil {
		return nil, err
	}
	sc.wAEAD = wAEAD

	return sc, nil
}

func newSecureConn(conn net.Conn) *SecureConn {
	return &SecureConn{
		Conn:    conn,
		lenBuf:  make([]byte, lenHdrLen+tagSize),
		payBuf:  make([]byte, maxChunk+tagSize),
		padBuf:  make([]byte, maxPad),
		frameBf: make([]byte, lenHdrLen+tagSize+maxChunk+tagSize+maxPad),
	}
}

// writeChunk seals a single (<= maxChunk) plaintext into one AEAD frame:
//
//	[enc (uint16 payloadLen || uint16 padLen)][tag] [enc payload][tag] [random padding]
//
// The trailing padding is cleartext but indistinguishable from the AEAD
// ciphertext preceding it; its length is authenticated inside the header, so an
// observer cannot tell payload from padding. Randomizing it per frame breaks
// size-fingerprinting (e.g. of the identical-looking warm-up pool connections).
func (c *SecureConn) writeChunk(plaintext []byte) error {
	padLen := randPad()

	var lenHdr [lenHdrLen]byte
	binary.BigEndian.PutUint16(lenHdr[0:2], uint16(len(plaintext)))
	binary.BigEndian.PutUint16(lenHdr[2:4], uint16(padLen))

	out := c.frameBf[:0]
	out = c.wAEAD.Seal(out, c.wNonce[:], lenHdr[:], nil)
	incrementNonce(&c.wNonce)
	out = c.wAEAD.Seal(out, c.wNonce[:], plaintext, nil)
	incrementNonce(&c.wNonce)

	if padLen > 0 {
		start := len(out)
		out = out[:start+padLen] // within frameBf capacity
		fillRandom(out[start:])
	}

	_, err := c.Conn.Write(out)
	return err
}

// Write splits p into AEAD-framed chunks and sends them.
func (c *SecureConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for total < len(p) {
		end := total + maxChunk
		if end > len(p) {
			end = len(p)
		}
		if err := c.writeChunk(p[total:end]); err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

// readChunk reads and opens one AEAD frame, discards its trailing padding, and
// returns the payload as a slice into c.payBuf.
func (c *SecureConn) readChunk() ([]byte, error) {
	// Length header.
	if _, err := io.ReadFull(c.Conn, c.lenBuf); err != nil {
		return nil, err
	}
	hdr, err := c.rAEAD.Open(c.lenBuf[:0], c.rNonce[:], c.lenBuf, nil)
	if err != nil {
		return nil, ErrAuth
	}
	incrementNonce(&c.rNonce)
	payloadLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	padLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if payloadLen == 0 || payloadLen > maxChunk || padLen > maxPad {
		return nil, errors.New("securestream: invalid chunk header")
	}

	// Payload block.
	enc := c.payBuf[:payloadLen+tagSize]
	if _, err := io.ReadFull(c.Conn, enc); err != nil {
		return nil, err
	}
	plain, err := c.rAEAD.Open(enc[:0], c.rNonce[:], enc, nil)
	if err != nil {
		return nil, ErrAuth
	}
	incrementNonce(&c.rNonce)

	// Discard the trailing random padding.
	if padLen > 0 {
		if _, err := io.ReadFull(c.Conn, c.padBuf[:padLen]); err != nil {
			return nil, err
		}
	}
	return plain, nil
}

// Read delivers decrypted payload bytes, buffering any remainder that does not
// fit in p. The remainder is copied into an owned buffer so the shared payBuf
// can be safely reused by the next readChunk.
func (c *SecureConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}

	plain, err := c.readChunk()
	if err != nil {
		return 0, err
	}

	n := copy(p, plain)
	if n < len(plain) {
		// Copy the remainder into an owned buffer; payBuf is reused next call.
		c.leftover = append(c.leftover[:0:0], plain[n:]...)
	}
	return n, nil
}

// randPad returns a random padding length in [0, maxPad]. The value is not
// security-sensitive (it only shapes on-wire sizes), so a fast non-crypto PRNG
// is used.
func randPad() int {
	return mrand.IntN(maxPad + 1)
}

// fillRandom fills b with non-patterned bytes so the cleartext padding blends
// with the AEAD ciphertext on the wire. Content is not security-sensitive.
func fillRandom(b []byte) {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], mrand.Uint64())
	}
	if i < len(b) {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], mrand.Uint64())
		copy(b[i:], t[:])
	}
}
