package pfilter

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type FilteredConn struct {
	source   *PacketFilter
	priority int

	recvBuffer chan packet

	filter Filter

	deadline time.Time
	closed   bool
	mut      sync.Mutex
}

// LocalAddr returns the local address
func (r *FilteredConn) LocalAddr() net.Addr {
	return r.source.LocalAddr()
}

// SetReadDeadline sets a read deadline
func (r *FilteredConn) SetReadDeadline(t time.Time) error {
	r.mut.Lock()
	r.deadline = t
	r.mut.Unlock()
	return nil
}

// SetWriteDeadline sets a write deadline
func (r *FilteredConn) SetWriteDeadline(t time.Time) error {
	return r.source.SetWriteDeadline(t)
}

// SetDeadline sets a read and a write deadline
func (r *FilteredConn) SetDeadline(t time.Time) error {
	r.SetReadDeadline(t)
	return r.SetWriteDeadline(t)
}

// WriteTo writes bytes to the given address
func (r *FilteredConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if r.filter != nil {
		r.filter.Outgoing(b, addr)
	}
	return r.source.WriteTo(b, addr)
}

// WriteTo reads from the filtered connection
func (r *FilteredConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	r.mut.Lock()
	timeout := time.After(r.deadline.Sub(time.Now()))
	r.mut.Unlock()

	select {
	case <-timeout:
		return 0, nil, &timeoutError{}
	case pkt := <-r.recvBuffer:
		copy(b, pkt.buf)
		bufPool.Put(pkt.buf)
		return pkt.n, pkt.addr, pkt.err
	}
}

// Closes the filtered connection
func (r *FilteredConn) Close() error {
	r.mut.Lock()
	defer r.mut.Unlock()
	if r.closed {
		return fmt.Errorf("use of closed connection")
	}
	r.closed = true
	r.source.removeConn(r)
	return nil
}
