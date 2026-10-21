package coreupdate

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func verifyFileHash(path, want string, size int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("coreupdate: %s is not a regular file", path)
	}
	if info.Size() != size {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrDownloadSizeMismatch, info.Size(), size)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, openedInfo) {
		return ErrTargetChanged
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%w: read %d bytes, want %d", ErrDownloadSizeMismatch, n, size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return ErrHashMismatch
	}
	return nil
}

func copyBackup(root, target string) (string, error) {
	src, err := os.Open(target)
	if err != nil {
		return "", err
	}
	defer src.Close()
	srcInfo, err := src.Stat()
	if err != nil {
		return "", err
	}
	if !srcInfo.Mode().IsRegular() {
		return "", fmt.Errorf("coreupdate: target is not a regular file")
	}
	dst, err := os.CreateTemp(root, backupPrefix+"*")
	if err != nil {
		return "", err
	}
	dstPath := dst.Name()
	keep := false
	defer func() {
		_ = dst.Close()
		if !keep {
			_ = os.Remove(dstPath)
		}
	}()
	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}
	if err := dst.Sync(); err != nil {
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}
	mode := srcInfo.Mode().Perm()
	if mode == 0 {
		mode = 0o600
	}
	if err := secureFile(dstPath, mode); err != nil {
		return "", err
	}
	if err := syncDir(root); err != nil {
		return "", err
	}
	keep = true
	return dstPath, nil
}
