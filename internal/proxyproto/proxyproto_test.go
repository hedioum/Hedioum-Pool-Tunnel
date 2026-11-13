package proxyproto

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// feed writes data to one end of a pipe and runs Accept on the other.
func feed(t *testing.T, data []byte) (net.Conn, error, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		a.Write(data)
	}()
	t.Cleanup(func() { a.Close(); b.Close() })
	c, err := Accept(b, 2*time.Second)
	return c, err, a
}

func TestV1(t *testing.T) {
	c, err, _ := feed(t, []byte("PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "203.0.113.9:51234" {
		t.Fatalf("remote = %s", got)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("payload after the header must be intact: %q %v", buf, err)
	}
}

func TestV1Unknown(t *testing.T) {
	c, err, _ := feed(t, []byte("PROXY UNKNOWN\r\nx"))
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr() == nil {
		t.Fatal("UNKNOWN must fall back to the socket peer")
	}
}

func v2(cmd, fam byte, body []byte) []byte {
	h := append([]byte{}, v2Sig...)
	h = append(h, 0x20|cmd, fam, 0, 0)
	binary.BigEndian.PutUint16(h[14:], uint16(len(body)))
	return append(h, body...)
}

func TestV2IPv4(t *testing.T) {
	body := []byte{203, 0, 113, 9, 198, 51, 100, 1, 0xC8, 0x32, 0x01, 0xBB} // src port 51250, dst 443
	c, err, _ := feed(t, append(v2(1, 0x11, body), "data"...))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "203.0.113.9:51250" {
		t.Fatalf("remote = %s", got)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "data" {
		t.Fatalf("payload: %q %v", buf, err)
	}
}

func TestV2IPv6(t *testing.T) {
	body := make([]byte, 36)
	copy(body[0:16], net.ParseIP("2001:db8::1"))
	binary.BigEndian.PutUint16(body[32:], 4444)
	c, err, _ := feed(t, v2(1, 0x21, body))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "[2001:db8::1]:4444" {
		t.Fatalf("remote = %s", got)
	}
}

func TestV2Local(t *testing.T) {
	if _, err, _ := feed(t, v2(0, 0, nil)); err != nil {
		t.Fatalf("LOCAL header must be accepted: %v", err)
	}
}

func TestRejectsPlainAndGarbage(t *testing.T) {
	for name, data := range map[string][]byte{
		"tls hello":   {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x00, 0x01},
		"http":        []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"bad v1":      []byte("PROXY TCP4 not-an-ip 1.2.3.4 1 2\r\n"),
		"v1 no crlf":  []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"),
		"v1 too long": append([]byte("PROXY TCP4 "), make([]byte, 200)...),
	} {
		if _, err, _ := feed(t, data); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestTimeoutWhenSilent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := Accept(b, 100*time.Millisecond); err == nil {
		t.Fatal("a silent connection must time out")
	}
}
