package pool

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// fakeConn is a no-op net.Conn for exercising monitoredStream in isolation.
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return nil }
func (fakeConn) RemoteAddr() net.Addr             { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

// TestMonitoredStreamCloseUnblocksRateLimit verifies that closing a stream
// cancels its context so a goroutine parked in the token-bucket WaitN returns
// promptly instead of waiting out the full delay (no goroutine leak on a dead
// connection).
func TestMonitoredStreamCloseUnblocksRateLimit(t *testing.T) {
	// 1 byte/sec with a 4-byte burst; drain the burst so any further wait is slow.
	ys := &YamuxSession{limiter: rate.NewLimiter(1, 4)}
	ys.limiter.AllowN(time.Now(), 4)

	ctx, cancel := context.WithCancel(context.Background())
	ms := &monitoredStream{Conn: fakeConn{}, parent: ys, ctx: ctx, cancel: cancel}

	start := time.Now()
	if err := ms.Close(); err != nil { // cancels ctx
		t.Fatalf("close: %v", err)
	}
	if _, err := ms.Write([]byte("payload-larger-than-burst")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Write blocked %v despite a canceled context", elapsed)
	}

	select {
	case <-ms.ctx.Done():
	default:
		t.Fatal("Close did not cancel the stream context")
	}
}
