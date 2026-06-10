package obfuscate

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
)

const (
	maxPayloadSize = 65535 // Max uint16 size for real data chunk (64KB)
	maxPaddingSize = 255   // Max uint8 size for random garbage (255B)
	headerSize     = 3     // 2 bytes payload length + 1 byte padding length
)

// PadConn injects and strips randomized garbage data (Padding) to alter TCP packet sizes dynamically.
// It implements a lightweight, zero-allocation custom framing protocol over the physical stream.
type PadConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex

	leftover  []byte // Slice pointing to unread data from the previous frame
	readBuf   []byte // Pre-allocated buffer for incoming payloads
	writeBuf  []byte // Pre-allocated buffer for outgoing frames
	headerBuf []byte // Fixed 3-byte array for reading headers
	padBuf    []byte // Fixed 255-byte array for discarding incoming garbage
}

// NewPadConn initializes the padding layer with pre-allocated memory to prevent GC pressure.
func NewPadConn(c net.Conn) *PadConn {
	return &PadConn{
		Conn:      c,
		readBuf:   make([]byte, maxPayloadSize),
		writeBuf:  make([]byte, headerSize+maxPayloadSize+maxPaddingSize),
		headerBuf: make([]byte, headerSize),
		padBuf:    make([]byte, maxPaddingSize),
	}
}

// Read extracts the real payload from the custom frame and discards the random padding.
func (c *PadConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// 1. Drain leftover data from the previous frame if available
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}

	// 2. Read Frame Header (3 bytes) strictly
	if _, err := io.ReadFull(c.Conn, c.headerBuf); err != nil {
		return 0, err
	}

	payloadLen := int(binary.BigEndian.Uint16(c.headerBuf[0:2]))
	padLen := int(c.headerBuf[2])

	// 3. Read Payload directly into our pre-allocated read buffer
	if payloadLen > 0 {
		if _, err := io.ReadFull(c.Conn, c.readBuf[:payloadLen]); err != nil {
			return 0, err
		}
	}

	// 4. Read and discard the random Padding (Garbage)
	if padLen > 0 {
		if _, err := io.ReadFull(c.Conn, c.padBuf[:padLen]); err != nil {
			return 0, err
		}
	}

	// 5. Deliver payload to the caller, keep any remainder in leftover
	if payloadLen > 0 {
		n := copy(p, c.readBuf[:payloadLen])
		if n < payloadLen {
			c.leftover = c.readBuf[n:payloadLen]
		}
		return n, nil
	}

	return 0, nil
}

// Write packages data into a custom frame, injecting randomized padding at the tail.
func (c *PadConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalWritten := 0
	pLen := len(p)

	for totalWritten < pLen {
		// Calculate chunk size ensuring we don't exceed maxPayloadSize
		chunkSize := pLen - totalWritten
		if chunkSize > maxPayloadSize {
			chunkSize = maxPayloadSize
		}

		// Generate random padding size (0 to 255 bytes)
		padLen := rand.Intn(maxPaddingSize + 1)

		// Construct Header
		binary.BigEndian.PutUint16(c.writeBuf[0:2], uint16(chunkSize))
		c.writeBuf[2] = byte(padLen)

		// Copy real payload into the frame buffer
		copy(c.writeBuf[headerSize:], p[totalWritten:totalWritten+chunkSize])

		// Inject random garbage at the end to randomize TCP packet sizes (Length Obfuscation)
		// OPTIMIZATION: Replaced the slow byte-by-byte loop with a single highly optimized bulk read.
		frameEnd := headerSize + chunkSize
		if padLen > 0 {
			// Using math/rand.Read to fill the slice in one operation is exponentially faster
			rand.Read(c.writeBuf[frameEnd : frameEnd+padLen])
		}

		totalFrameSize := frameEnd + padLen

		// Dispatch the full obfuscated frame to the OS socket
		if _, err := c.Conn.Write(c.writeBuf[:totalFrameSize]); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
	}

	return totalWritten, nil
}
