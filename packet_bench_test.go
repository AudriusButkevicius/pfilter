package pfilter

import (
	"net"
	"testing"
	"time"
)

func BenchmarkFilteredPacket(b *testing.B) {
	for _, batch := range []struct {
		name string
		size int
	}{{"Unbatched", 0}, {"Batch1", 1}, {"Batch8", 8}} {
		b.Run(batch.name, func(b *testing.B) {
			sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer sock.Close()
			f, err := NewPacketFilterWithConfig(Config{
				Conn: sock, BufferSize: 1500, Backlog: 256, BatchSize: batch.size,
			})
			if err != nil {
				b.Fatal(err)
			}
			c := f.NewConn(1, nil)
			defer c.Close()
			f.Start()
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer peer.Close()
			msg := []byte("packet")
			buf := make([]byte, 1500)
			addr := sock.LocalAddr()
			if err := c.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := peer.WriteTo(msg, addr); err != nil {
					b.Fatal(err)
				}
				if _, _, err := c.ReadFrom(buf); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}
