package pfilter

import (
	"testing"
	"time"
)

// Returning a buffer to the pool must not allocate.
func TestBufPoolPutDoesNotAllocate(t *testing.T) {
	p := newBufPool(1500)
	b := p.get()
	if n := testing.AllocsPerRun(1000, func() { p.put(b); b = p.get() }); n != 0 {
		t.Fatalf("%v allocations per put and get", n)
	}
}

func TestBufPoolFullAndEmptyNeverBlock(t *testing.T) {
	p := newBufPool(1500)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Exhaust the free list, then return more buffers than it can retain.
		buffers := make([][]byte, cap(p.free)+1)
		for i := range buffers {
			buffers[i] = p.get()
			if len(buffers[i]) != 1500 {
				t.Errorf("buffer length %d, want 1500", len(buffers[i]))
			}
		}
		for _, buf := range buffers {
			p.put(buf)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pool blocked when empty or full")
	}
	if len(p.free) != cap(p.free) {
		t.Fatalf("retained %d buffers, want %d", len(p.free), cap(p.free))
	}
}
