package pfilter

import (
	"net"
	"sync/atomic"
	"time"
)

type FilteredConn struct {
	source   *PacketFilter
	priority int

	recvBuffer chan packet

	filter Filter

	deadline atomic.Value
	closed   int32
}

// LocalAddr returns the local address
func (r *FilteredConn) LocalAddr() net.Addr {
	return r.source.LocalAddr()
}

// SetReadDeadline sets a read deadline
func (r *FilteredConn) SetReadDeadline(t time.Time) error {
	r.deadline.Store(t)
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
	if atomic.LoadInt32(&r.closed) == 1 {
		return 0, errClosed
	}

	if r.filter != nil {
		r.filter.Outgoing(b, addr)
	}
	return r.source.WriteTo(b, addr)
}

// ReadFrom reads from the filtered connection
func (r *FilteredConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if atomic.LoadInt32(&r.closed) == 1 {
		return 0, nil, errClosed
	}

	var timeout <-chan time.Time

	if deadline, ok := r.deadline.Load().(time.Time); ok && !deadline.IsZero() {
		timeout = time.After(deadline.Sub(time.Now()))
	}

	select {
	case <-timeout:
		return 0, nil, &timeoutError{}
	case pkt := <-r.recvBuffer:
		copy(b[:pkt.n], pkt.buf)
		bufPool.Put(pkt.buf[:maxPacketSize])
		return pkt.n, pkt.addr, pkt.err
	}
}

// Close closes the filtered connection, removing it's filters
func (r *FilteredConn) Close() error {
	if atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		r.source.removeConn(r)
		return nil
	}
	return errClosed
}
