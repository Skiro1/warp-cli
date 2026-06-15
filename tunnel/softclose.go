//go:build windows

package tunnel

import (
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// nativeTunLayout mirrors tun.NativeTun field offsets for unsafe access.
// Fields: wt *wintun.Adapter, name string, handle uintptr, rate, session, readWait, events, running, closeOnce, close, forcedMTU, outSizes
type nativeTunLayout struct {
	wt        *wintun.Adapter
	name      string
	handle    uintptr
	_         [32]byte // rate (rateJuggler - multiple atomics)
	session   wintun.Session
	readWait  windows.Handle
	events    chan tun.Event
	running   sync.WaitGroup
	closeOnce sync.Once
	close     atomic.Bool
	forcedMTU int
	_         [24]byte // outSizes []int
}

// SoftTun wraps a tun.Device and provides safe close sequence:
// - Close() is a no-op (prevents device.Close() from destroying the adapter)
// - SoftClose() ends the Wintun session (stops packet I/O) but keeps the adapter alive
// - DestroyAdapter() removes the Wintun adapter from the system
// Events() filters out tun.EventDown to prevent RoutineTUNEventReader from calling device.Close()
type SoftTun struct {
	inner    tun.Device
	closed   atomic.Bool
	destroyS sync.Once
	events   chan tun.Event
}

func newSoftTun(d tun.Device) *SoftTun {
	return &SoftTun{
		inner:  d,
		events: make(chan tun.Event, 16),
	}
}

// Close is a no-op. It prevents device.Close() from destroying the TUN adapter.
// The real cleanup is done via SoftClose() + DestroyAdapter().
func (s *SoftTun) Close() error {
	return nil
}

// SoftClose ends the Wintun session (stops packet I/O) but keeps the adapter alive.
// The adapter can be destroyed later with DestroyAdapter().
func (s *SoftTun) SoftClose() error {
	if s.closed.Swap(true) {
		return nil
	}

	nt := s.inner.(*tun.NativeTun)
	layout := (*nativeTunLayout)(unsafe.Pointer(nt))

	// Signal close flag + wake readWait (same as NativeTun.Close)
	layout.close.Store(true)
	windows.SetEvent(layout.readWait)

	// Wait for running goroutines to finish (same as NativeTun.Close)
	layout.running.Wait()

	// End the session (stops packet I/O) but do NOT close the adapter
	layout.session.End()

	// Drain the events channel to prevent RoutineTUNEventReader from
	// receiving a stale event and calling device.Close()
	select {
	case <-s.events:
	default:
	}

	return nil
}

// DestroyAdapter removes the Wintun adapter from the system.
// Call this only after SoftClose + routes are restored.
func (s *SoftTun) DestroyAdapter() {
	s.destroyS.Do(func() {
		nt := s.inner.(*tun.NativeTun)
		layout := (*nativeTunLayout)(unsafe.Pointer(nt))

		if layout.wt != nil {
			layout.wt.Close()
			layout.wt = nil
		}
	})
}

func (s *SoftTun) Name() (string, error)       { return s.inner.Name() }
func (s *SoftTun) MTU() (int, error)            { return s.inner.MTU() }

// Events returns a filtered event channel that drops tun.EventDown.
// This prevents RoutineTUNEventReader from calling device.Close() when the
// Wintun session ends.
func (s *SoftTun) Events() <-chan tun.Event {
	go func() {
		for evt := range s.inner.Events() {
			if evt == tun.EventDown {
				// Drop EventDown — we handle shutdown ourselves via SoftClose()
				continue
			}
			s.events <- evt
		}
	}()
	return s.events
}

func (s *SoftTun) Read(b [][]byte, s2 []int, o int) (int, error) { return s.inner.Read(b, s2, o) }
func (s *SoftTun) Write(b [][]byte, o int) (int, error)          { return s.inner.Write(b, o) }
func (s *SoftTun) File() *os.File                                { return nil }
func (s *SoftTun) BatchSize() int                                { return s.inner.BatchSize() }