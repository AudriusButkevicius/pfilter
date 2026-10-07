package pfilter

import (
	"net"
	"testing"
	"time"
)

// Returning a buffer to the pool must not allocate.
func TestBufPoolPutDoesNotAllocate(t *testing.T) {
	p := newBufPool(1500)
	b := p.get()
	if n := testing.AllocsPerRun(1000, func() { p.put(b); b = p.get() }); n != 0 {
		t.Fatalf("%v allocations per put and get", n)
	}
}

func BenchmarkFilteredPacket(b *testing.B) {
	sock, _ := net.ListenPacket("udp", "127.0.0.1:0")
	f := NewPacketFilter(sock)
	c := f.NewConn(1, nil)
	f.Start()
	peer, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer peer.Close()
	defer sock.Close()
	msg := []byte("x")
	buf := make([]byte, 1500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer.WriteTo(msg, sock.LocalAddr())
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := c.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}
