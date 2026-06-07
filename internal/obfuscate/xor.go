package obfuscate

import (
	"net"
	"sync"
)

// bufferPool ensures zero-allocation during XOR stream writes.
// We reuse 32KB buffers to avoid putting pressure on the Go Garbage Collector under heavy load.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// XorConn wraps a net.Conn and applies a highly optimized, stateful XOR stream cipher.
type XorConn struct {
	net.Conn
	key        []byte
	readIndex  int
	writeIndex int
}

// NewXorConn initializes the XOR wrapper. The AuthToken acts as the symmetric encryption key.
func NewXorConn(conn net.Conn, token string) *XorConn {
	return &XorConn{
		Conn:       conn,
		key:        []byte(token),
		readIndex:  0,
		writeIndex: 0,
	}
}

// Read intercepts incoming data and decrypts it in-place.
func (c *XorConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		kLen := len(c.key)
		if kLen > 0 {
			for i := 0; i < n; i++ {
				b[i] ^= c.key[c.readIndex]
				c.readIndex = (c.readIndex + 1) % kLen
			}
		}
	}
	return n, err
}

// Write encrypts outbound data before sending it to the physical TCP socket.
func (c *XorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	kLen := len(c.key)
	if kLen == 0 {
		return c.Conn.Write(b)
	}

	// Fetch a reusable temporary buffer from the memory pool
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	var totalWritten int

	// Process large payloads in chunks to fit inside our 32KB pooled buffer
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > len(buf) {
			chunkSize = len(buf)
		}

		// Apply XOR mask to the temporary buffer
		for i := 0; i < chunkSize; i++ {
			buf[i] = b[i] ^ c.key[c.writeIndex]
			c.writeIndex = (c.writeIndex + 1) % kLen
		}

		// Write the obfuscated chunk to the underlying connection
		n, err := c.Conn.Write(buf[:chunkSize])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		// Shift the remaining slice forward
		b = b[chunkSize:]
	}

	return totalWritten, nil
}
