//go:build windows

package netpolicy

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ChangeNotifier coalesces Windows IP Helper notifications for interface,
// address, and route-table changes. The channel is intentionally unbuffered
// from the consumer's perspective but has one pending slot: a burst of OS
// notifications produces one wake-up while the consumer is busy.
type ChangeNotifier interface {
	Changes() <-chan struct{}
	Err() error
	Close() error
}

type windowsChangeNotifier struct {
	changes chan struct{}
	closed  atomic.Bool
	once    sync.Once
	errMu   sync.Mutex
	err     error

	interfaceHandle windows.Handle
	addressHandle   windows.Handle
	routeHandle     windows.Handle

	interfaceCallback uintptr
	addressCallback   uintptr
	routeCallback     uintptr
}

var (
	iphlpapi               = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyRouteChange2 = iphlpapi.NewProc("NotifyRouteChange2")
)

func NewChangeNotifier() (ChangeNotifier, error) {
	n := &windowsChangeNotifier{changes: make(chan struct{}, 1)}
	n.interfaceCallback = windows.NewCallback(func(_, _, _ uintptr) uintptr {
		n.signal()
		return 0
	})
	n.addressCallback = windows.NewCallback(func(_, _, _ uintptr) uintptr {
		n.signal()
		return 0
	})
	n.routeCallback = windows.NewCallback(func(_, _, _ uintptr) uintptr {
		n.signal()
		return 0
	})

	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, n.interfaceCallback, nil, false, &n.interfaceHandle); err != nil {
		return nil, err
	}
	if err := windows.NotifyUnicastIpAddressChange(windows.AF_UNSPEC, n.addressCallback, nil, false, &n.addressHandle); err != nil {
		_ = n.Close()
		return nil, err
	}
	if err := notifyRouteChange2(n.routeCallback, &n.routeHandle); err != nil {
		_ = n.Close()
		return nil, err
	}
	return n, nil
}

func notifyRouteChange2(callback uintptr, handle *windows.Handle) error {
	if err := procNotifyRouteChange2.Find(); err != nil {
		return err
	}
	var notificationHandle windows.Handle
	r1, _, err := syscall.Syscall6(procNotifyRouteChange2.Addr(), 5,
		uintptr(windows.AF_INET), callback, 0, 0, uintptr(unsafe.Pointer(&notificationHandle)), 0)
	if r1 != 0 {
		if err == syscall.Errno(0) {
			err = syscall.Errno(r1)
		}
		return err
	}
	*handle = notificationHandle
	return nil
}

func (n *windowsChangeNotifier) signal() {
	if n == nil || n.closed.Load() {
		return
	}
	select {
	case n.changes <- struct{}{}:
	default:
	}
}

func (n *windowsChangeNotifier) Changes() <-chan struct{} {
	if n == nil {
		return nil
	}
	return n.changes
}

func (n *windowsChangeNotifier) Err() error {
	if n == nil {
		return nil
	}
	n.errMu.Lock()
	defer n.errMu.Unlock()
	return n.err
}

func (n *windowsChangeNotifier) Close() error {
	if n == nil {
		return nil
	}
	n.once.Do(func() {
		n.closed.Store(true)
		var closeErr error
		for _, handle := range []windows.Handle{n.interfaceHandle, n.addressHandle, n.routeHandle} {
			if handle != 0 {
				if err := windows.CancelMibChangeNotify2(handle); err != nil && closeErr == nil {
					closeErr = err
				}
			}
		}
		n.errMu.Lock()
		n.err = closeErr
		n.errMu.Unlock()
	})
	n.errMu.Lock()
	defer n.errMu.Unlock()
	return n.err
}
