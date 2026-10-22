package pfilter

import (
	"net"
	"testing"
	"time"
)

func TestBatchReaderPreservesQueuedPackets(t *testing.T) {
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	if err := sock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f, err := NewPacketFilterWithConfig(Config{Conn: sock, BufferSize: 1500, Backlog: 4, BatchSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	c := f.NewConn(1, nil)
	defer c.Close()
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	read := f.batchReader()
	for _, payload := range []string{"first", "second"} {
		if _, err := peer.WriteTo([]byte(payload), sock.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		msgs := read()
		if len(msgs) != 1 || msgs[0].Err != nil {
			t.Fatalf("read got %v", msgs)
		}
		f.conns[0].recvBuffer <- msgs[0]
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	for _, want := range []string{"first", "second"} {
		n, _, err := c.ReadFrom(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("read %q, %v; want %q", buf[:n], err, want)
		}
	}
	if err := sock.Close(); err != nil {
		t.Fatal(err)
	}
	msgs := read()
	if len(msgs) != 1 || msgs[0].Err == nil {
		t.Fatalf("closed socket read got %v", msgs)
	}
	f.returnBuffers(msgs[0].Message)
}
