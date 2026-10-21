//go:build !windows

package coreupdate

import "os"

func secureDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func secureFile(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
