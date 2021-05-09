package pfilter

import (
	"io"
	"math/rand"
	"net"
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
	pfilter.Start()
	pfilterServer := pfilter.NewConn(10, nil)

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
