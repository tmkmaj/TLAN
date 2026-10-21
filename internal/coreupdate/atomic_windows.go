//go:build windows

package coreupdate

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32Atomic = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileEx = kernel32Atomic.NewProc("MoveFileExW")
)

func atomicReplaceFile(src, dst string) error {
	srcPtr, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return fmt.Errorf("encode source path: %w", err)
	}
	dstPtr, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return fmt.Errorf("encode destination path: %w", err)
	}
	ok, _, callErr := procMoveFileEx.Call(
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if ok == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			return fmt.Errorf("MoveFileExW failed")
		}
		return fmt.Errorf("MoveFileExW: %w", callErr)
	}
	return nil
}

func syncDir(path string) error {
	// MOVEFILE_WRITE_THROUGH flushes the rename; Windows does not provide a
	// portable directory fsync through the standard os package.
	return nil
}
