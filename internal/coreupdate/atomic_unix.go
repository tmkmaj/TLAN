//go:build !windows

package coreupdate

import "os"

func atomicReplaceFile(src, dst string) error {
	return os.Rename(src, dst)
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
