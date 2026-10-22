package pfilter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

type prefixFilter byte

func (f prefixFilter) Outgoing([]byte, net.Addr) {}

func (f prefixFilter) ClaimIncoming(b []byte, _ net.Addr) bool {
	return len(b) > 0 && b[0] == byte(f)
}

func TestPacketReceiver(t *testing.T) {
	for _, batch := range []int{0, 8} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) { testPacketReceiver(t, batch) })
	}
}

func testPacketReceiver(t *testing.T, batch int) {
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	f, err := NewPacketFilterWithConfig(Config{Conn: sock, BufferSize: 1500, Backlog: 16, BatchSize: batch})
	if err != nil {
		t.Fatal(err)
	}
	pushed := f.NewConn(1, prefixFilter('r'))
	defer pushed.Close()
	queued := f.NewConn(2, nil)
	defer queued.Close()

	type got struct {
		b   []byte
		err error
	}
	ch := make(chan got, 16)
	pushed.(PacketReceiver).SetPacketReceiver(func(b []byte, _ net.Addr, err error) {
		ch <- got{append([]byte(nil), b...), err}
	})
	f.Start()

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, data := range []string{"r1", "q1"} {
		if _, err := peer.WriteTo([]byte(data), sock.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case g := <-ch:
		if g.err != nil || !bytes.Equal(g.b, []byte("r1")) {
			t.Fatalf("receiver got %q, %v", g.b, g.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver not called")
	}

	if err := queued.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
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
	if err := queued.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := queued.ReadFrom(buf); err == nil {
		t.Fatal("queued connection was not told about the read error")
	}
}

// Exercise dispatch with a deterministic sequence, including the terminal error.
func runReceiverLoop(t *testing.T, f *PacketFilter, packets int) error {
	t.Helper()
	terminal := errors.New("terminal read error")
	i := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.loop(func() []messageWithError {
			buf := make([]byte, f.packetSize)
			buf[0] = byte(i)
			msg := messageWithError{Message: ipv4.Message{Buffers: [][]byte{buf[:1]}, N: 1}}
			if i == packets {
				msg.Err = terminal
			}
			i++
			return []messageWithError{msg}
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver loop blocked")
	}
	return terminal
}

func receiverFixture(t *testing.T) (*PacketFilter, PacketReceiver) {
	t.Helper()
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	f := NewPacketFilter(sock)
	c := f.NewConn(1, nil).(PacketReceiver)
	t.Cleanup(func() { c.Close() })
	return f, c
}

func TestPacketReceiverCanDisableItself(t *testing.T) {
	f, c := receiverFixture(t)
	c.SetPacketReceiver(nil)
	calls := 0
	c.SetPacketReceiver(func(b []byte, _ net.Addr, err error) {
		calls++
		if err != nil || len(b) != 1 || b[0] != 0 {
			t.Errorf("unexpected callback: %v, %v", b, err)
		}
		c.SetPacketReceiver(nil)
	})
	terminal := runReceiverLoop(t, f, 2)
	buf := make([]byte, 8)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := c.ReadFrom(buf)
	if err != nil || n != 1 || buf[0] != 1 || calls != 1 {
		t.Fatalf("queued packet = %v, %v; callback calls = %d", buf[:n], err, calls)
	}
	if _, _, err := c.ReadFrom(buf); !errors.Is(err, terminal) {
		t.Fatalf("queued error = %v, want %v", err, terminal)
	}
}

func TestPacketReceiverCanCloseConnection(t *testing.T) {
	f, c := receiverFixture(t)
	calls := 0
	c.SetPacketReceiver(func(_ []byte, _ net.Addr, err error) {
		calls++
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	runReceiverLoop(t, f, 2)
	if calls != 1 || f.NumberOfConns() != 0 {
		t.Fatalf("callback calls = %d, connections = %d", calls, f.NumberOfConns())
	}
}

func TestPacketReceiverConcurrentReplacement(t *testing.T) {
	f, c := receiverFixture(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			c.SetPacketReceiver(func([]byte, net.Addr, error) {})
			c.SetPacketReceiver(nil)
		}
	}()
	runReceiverLoop(t, f, 1000)
	wg.Wait()
}
