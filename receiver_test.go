package pfilter

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type prefixFilter byte

func (f prefixFilter) Outgoing([]byte, net.Addr) {}

func (f prefixFilter) ClaimIncoming(b []byte, _ net.Addr) bool {
	return len(b) > 0 && b[0] == byte(f)
}

func TestPacketReceiver(t *testing.T) {
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := NewPacketFilter(sock)
	pushed := f.NewConn(1, prefixFilter('r'))
	queued := f.NewConn(2, nil)

	type got struct {
		b   []byte
		err error
	}
	ch := make(chan got, 16)
	pushed.(interface {
		SetPacketReceiver(func([]byte, net.Addr, error))
	}).SetPacketReceiver(func(b []byte, _ net.Addr, err error) {
		ch <- got{append([]byte(nil), b...), err}
	})
	f.Start()

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.WriteTo([]byte("r1"), sock.LocalAddr())
	peer.WriteTo([]byte("q1"), sock.LocalAddr())

	select {
	case g := <-ch:
		if g.err != nil || !bytes.Equal(g.b, []byte("r1")) {
			t.Fatalf("receiver got %q, %v", g.b, g.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver not called")
	}

	queued.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, _, err := queued.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "q1" {
		t.Fatalf("queued conn read %q, %v", buf[:n], err)
	}

	sock.Close()
	select {
	case g := <-ch:
		if g.err == nil {
			t.Fatalf("receiver got %q after close, want an error", g.b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver not told about the read error")
	}
}
