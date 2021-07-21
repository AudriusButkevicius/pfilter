package pfilter

import (
	"errors"
	"github.com/lucas-clemente/quic-go"
	"io"
	"net"
	"syscall"
	"time"
)

var _ quic.OOBCapablePacketConn = (*filteredConnObb)(nil)

type filteredConnObb struct {
	*filteredConn
}

func (r *filteredConnObb) SyscallConn() (syscall.RawConn, error) {
	if r.source.oobConn != nil {
		return r.source.oobConn.SyscallConn()
	}
	if scon, ok := r.source.conn.(interface{
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return scon.SyscallConn()
	}
	return nil, errors.New("doesn't have a SyscallConn")
}

func (r *filteredConnObb) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return r.source.oobConn.WriteMsgUDP(b, oob, addr)
}

func (r *filteredConnObb) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	select {
	case <-r.closed:
		return 0, 0, 0, nil, errClosed
	default:
	}

	var timeout <-chan time.Time

	if deadline, ok := r.deadline.Load().(time.Time); ok && !deadline.IsZero() {
		timer := time.NewTimer(deadline.Sub(time.Now()))
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case <-timeout:
		return 0, 0, 0, nil, errTimeout
	case msg := <-r.recvBuffer:
		err := msg.Err

		n := msg.N
		if l := len(b); l < n {
			n = l
			if err == nil {
				err = io.ErrShortBuffer
			}
		}
		copy(b, msg.Buffers[0][:n])

		oobn := msg.NN
		if oobl := len(oob); oobl < oobn {
			oobn = oobl
		}
		if oobn > 0 {
			copy(oob, msg.OOB[:oobn])
		}

		r.source.returnBuffers(msg.Message)

		return n, oobn, msg.Flags, msg.Addr.(*net.UDPAddr), err
	case <-r.closed:
		return 0, 0, 0, nil, errClosed
	}
}
