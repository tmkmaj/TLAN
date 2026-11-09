//go:build !windows

package main

import (
	"fmt"
	"os"
)

func checkPrivateFile(_ string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("mode %04o allows access by group or others", mode)
	}
	if mode&0o400 == 0 {
		return fmt.Errorf("mode %04o is not readable by its owner", mode)
	}
	return nil
}
