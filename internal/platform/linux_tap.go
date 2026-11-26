//go:build linux

package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	linuxTUNPath   = "/dev/net/tun"
	linuxTUNSETIFF = 0x400454CA
	linuxIFFTAP    = 0x0002
	linuxIFFNoPI   = 0x1000
	linuxIFNAMSIZ  = 16
)

// linuxIfreq is the Linux ifreq layout used by TUNSETIFF. The trailing bytes
// keep the structure large enough for the kernel's 64-bit ABI while the name
// and flags fields match the ioctl contract.
type linuxIfreq struct {
	Name  [linuxIFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// LinuxTAP is a raw Ethernet TAP device. It deliberately exposes complete
// Ethernet frames, matching the portable Adapter contract and the L2 bridge.
type LinuxTAP struct {
	file      *os.File
	name      string
	mtu       int
	closeOnce sync.Once
}

func OpenLinuxTAP(name string, mtu int) (*LinuxTAP, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "tlan0"
	}
	if len(name) >= linuxIFNAMSIZ {
		return nil, fmt.Errorf("TAP interface name must be fewer than %d bytes", linuxIFNAMSIZ)
	}
	if mtu <= 0 {
		mtu = 1500
	}
	if mtu > 65535 {
		return nil, errors.New("TAP MTU exceeds maximum Ethernet payload")
	}
	file, err := os.OpenFile(linuxTUNPath, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", linuxTUNPath, err)
	}
	var request linuxIfreq
	copy(request.Name[:], name)
	request.Flags = linuxIFFTAP | linuxIFFNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), linuxTUNSETIFF, uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("configure TAP %q: %w", name, errno)
	}
	actual := string(request.Name[:])
	if index := strings.IndexByte(actual, 0); index >= 0 {
		actual = actual[:index]
	}
	if actual == "" {
		actual = name
	}
	return &LinuxTAP{file: file, name: actual, mtu: mtu}, nil
}

func (t *LinuxTAP) Name() string {
	if t == nil || t.name == "" {
		return "linux-tap"
	}
	return t.name
}

func (t *LinuxTAP) MTU() int {
	if t == nil {
		return 0
	}
	return t.mtu
}

func (t *LinuxTAP) ReadFrame() ([]byte, error) {
	if t == nil || t.file == nil {
		return nil, io.ErrClosedPipe
	}
	buffer := make([]byte, t.mtu+14)
	count, err := t.file.Read(buffer)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func (t *LinuxTAP) WriteFrame(frame []byte) error {
	if t == nil || t.file == nil {
		return io.ErrClosedPipe
	}
	if len(frame) < 14 {
		return errors.New("TAP frame is shorter than an Ethernet header")
	}
	if len(frame) > t.mtu+14 {
		return errors.New("TAP frame exceeds configured MTU")
	}
	count, err := t.file.Write(frame)
	if err != nil {
		return err
	}
	if count != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

func (t *LinuxTAP) Close() error {
	if t == nil || t.file == nil {
		return nil
	}
	var err error
	t.closeOnce.Do(func() { err = t.file.Close() })
	return err
}
