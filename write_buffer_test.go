package pfilter

import (
	"errors"
	"net"
	"testing"
)

type writeBufferConn struct {
	net.PacketConn
	size int
	err  error
}

func (c *writeBufferConn) SetWriteBuffer(size int) error {
	c.size = size
	return c.err
}

func setWriteBuffer(t *testing.T, c net.PacketConn, size int) error {
	t.Helper()
	setter, ok := c.(interface{ SetWriteBuffer(int) error })
	if !ok {
		t.Fatal("filtered connection does not expose SetWriteBuffer")
	}
	return setter.SetWriteBuffer(size)
}

func TestSetWriteBuffer(t *testing.T) {
	wantErr := errors.New("cannot resize buffer")
	for _, underlyingErr := range []error{nil, wantErr} {
		underlying := &writeBufferConn{err: underlyingErr}
		conn := NewPacketFilter(underlying).NewConn(1, nil)
		defer conn.Close()
		if err := setWriteBuffer(t, conn, 64<<10); err != underlyingErr {
			t.Fatalf("got error %v, want %v", err, underlyingErr)
		}
		if underlying.size != 64<<10 {
			t.Fatalf("forwarded size %d, want %d", underlying.size, 64<<10)
		}
	}
}

func TestSetWriteBufferUnsupported(t *testing.T) {
	// Expose only net.PacketConn, hiding optional socket capabilities.
	conn := NewPacketFilter(struct{ net.PacketConn }{}).NewConn(1, nil)
	defer conn.Close()
	if err := setWriteBuffer(t, conn, 64<<10); !errors.Is(err, errNotSupported) {
		t.Fatalf("got error %v, want %v", err, errNotSupported)
	}
}

func TestSetWriteBufferOOBConnection(t *testing.T) {
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	conn := NewPacketFilter(sock).NewConn(1, nil)
	defer conn.Close()
	if _, ok := conn.(*filteredConnObb); !ok {
		t.Fatal("expected an OOB-capable filtered connection")
	}
	if err := setWriteBuffer(t, conn, 64<<10); err != nil {
		t.Fatal(err)
	}
	if err := sock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setWriteBuffer(t, conn, 64<<10); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got error %v, want closed socket error", err)
	}
}
