package pfilter

import (
	"io"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
)

const packetSize = 1500

func BenchmarkPacketConn(b *testing.B) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	benchmark(b, client, &readerWrapper{server}, packetSize)
}

func BenchmarkPacketConnPfilter(b *testing.B) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	pfilter := NewPacketFilter(server)
	pfilterServer := pfilter.NewConn(10, nil)
	pfilter.Start()

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	benchmark(b, client, &readerWrapper{pfilterServer}, packetSize)
}

func benchmark(b *testing.B, client io.Writer, server io.Reader, sz int) {
	data := make([]byte, sz)
	if _, err := rand.Read(data); err != nil {

		b.Fatal(err)
	}

	total := 0
	wg := sync.WaitGroup{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(2)
		go func() {
			if err := sendMsg(client, data); err != nil {
				b.Fatal(err)
			}
			wg.Done()
		}()
		go func() {
			if err := recvMsg(server, data); err != nil {
				b.Fatal(err)
			}
			total += sz
			wg.Done()
		}()
		wg.Wait()
	}
	b.ReportAllocs()
	b.SetBytes(int64(total / b.N))
}

type readerWrapper struct {
	conn net.PacketConn
}

func (r *readerWrapper) Read(buf []byte) (int, error) {
	n, _, err := r.conn.ReadFrom(buf)
	return n, err
}

func sendMsg(c io.Writer, buf []byte) error {
	n, err := c.Write(buf)
	if n != len(buf) || err != nil {
		return err
	}
	return nil
}

func recvMsg(c io.Reader, buf []byte) error {
	for read := 0; read != len(buf); {
		n, err := c.Read(buf)
		read += n
		if err != nil {
			return err
		}
	}
	return nil
}

func TestShortRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("seems this is only true on windows")
	}

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	d := make([]byte, 1024)

	rand.Read(d)

	if err := sendMsg(client, d); err != nil {
		t.Fatal(err)
	}

	small := make([]byte, 32)

	n, _, err := server.ReadFrom(small)
	if err == nil {
		t.Error("expected read to fail")
	}
	if n != 32 {
		t.Error("unexpected read", n)
	}
	if nerr, ok := err.(net.Error); !ok || nerr.Temporary() {
		t.Error("unexpected error condition", ok, nerr.Temporary())
	}
}
