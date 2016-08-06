package pfilter

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
)

// Filter object receives all data sent out on the Outgoing callback,
// and is expected to decide if it wants to receive the packet or not via
// the Receive callback
type Filter interface {
	Outgoing([]byte, net.Addr)
	ClaimIncoming([]byte, net.Addr) bool
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

	dropped uint64
}

// NewConn returns a new net.PacketConn object which filters packets based
// on the provided filter. If filter is nil, the connection will receive all
// packets. Priority decides which connection gets the ability to claim the packet.
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

// Dropped returns number of packets dropped due to nobody claiming them.
func (d *PacketFilter) Dropped() uint64 {
	return atomic.LoadUint64(&d.dropped)
}

func (d *PacketFilter) run() {
	var buf []byte
next:
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
		conns := d.conns
		d.mut.Unlock()
		for _, conn := range conns {
			if conn.filter == nil || conn.filter.ClaimIncoming(pkt.buf, pkt.addr) {
				conn.recvBuffer <- pkt
				goto next
			}
		}

		atomic.AddUint64(&d.dropped, 1)
	}
}
