package pfilter

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// Filter object receives all data sent out on the Outgoing callback,
// and is expected to decide if it wants to receive the packet or not via
// the Receive callback
type Filter interface {
	Outgoing([]byte, net.Addr)
	Receive([]byte, net.Addr) bool
}

// NewPacketFilter creates a packet filter object wrapping the given packet
// connection.
func NewPacketFilter(conn net.PacketConn) *PacketFilter {
	d := &PacketFilter{
		PacketConn: conn,
	}
	go d.run()
	return d
}

// PacketFilter embeds a net.PacketConn to perform the filtering.
type PacketFilter struct {
	net.PacketConn
	conns     []*FilteredConn
	startOnce sync.Once
	mut       sync.Mutex
}

// NewConn returns a new net.PacketConn object which filters packets based
// on the provided filter. If filter is nil, the connection will receive all
// packets. Priority decides which connection gets the packet first.
func (d *PacketFilter) NewConn(priority int, filter Filter) (net.PacketConn, error) {
	conn := &FilteredConn{
		priority:   priority,
		source:     d,
		recvBuffer: make(chan packet, 1024),
		filter:     filter,
	}
	d.mut.Lock()
	d.conns = append(d.conns, conn)
	sort.Sort(filteredConnList(d.conns))
	d.mut.Unlock()
	return conn, nil
}

func (d *PacketFilter) removeConn(r *FilteredConn) {
	d.mut.Lock()
	for i, conn := range d.conns {
		if conn == r {
			copy(d.conns[i:], d.conns[i+1:])
			d.conns[len(d.conns)-1] = nil
			d.conns = d.conns[:len(d.conns)-1]
			break
		}
	}
	d.mut.Unlock()
}

// NumberOfConns returns the number of currently active virtual connections
func (d *PacketFilter) NumberOfConns() int {
	d.mut.Lock()
	n := len(d.conns)
	d.mut.Unlock()
	return n
}

func (d *PacketFilter) run() {
	var buf []byte
	for {
		buf = bufPool.Get().([]byte)
		n, addr, err := d.ReadFrom(buf[:maxPacketSize])
		pkt := packet{
			n:    n,
			addr: addr,
			err:  err,
			buf:  buf[:n],
		}

		d.mut.Lock()
		for _, conn := range d.conns {
			if conn.filter == nil || conn.filter.Receive(pkt.buf, pkt.addr) {
				conn.recvBuffer <- pkt
				goto dispatched
			}
		}

		fmt.Println("dropped")

	dispatched:
		d.mut.Unlock()
	}
}
