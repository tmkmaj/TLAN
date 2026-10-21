package coreupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	stateFileName      = ".coreupdate-state.json"
	tempDownloadPrefix = ".coreupdate-download-"
	tempStatePrefix    = ".coreupdate-state-"
	backupPrefix       = ".coreupdate-backup-"
	maxStateBytes      = 64 << 10
)

func prepareRoot(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: core root is empty", ErrInvalidTarget)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("coreupdate: resolve core root: %w", err)
	}
	info, err := os.Lstat(abs)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: core root is a symbolic link", ErrSymlink)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("coreupdate: core root is not a directory")
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", fmt.Errorf("coreupdate: create core root: %w", err)
		}
	default:
		return "", fmt.Errorf("coreupdate: inspect core root: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("coreupdate: resolve core root symlinks: %w", err)
	}
	if !pathsEqual(abs, real) {
		return "", fmt.Errorf("%w: core root path contains a symbolic link", ErrSymlink)
	}
	if err := secureDirectory(real); err != nil {
		return "", fmt.Errorf("coreupdate: secure core root: %w", err)
	}
	return filepath.Clean(real), nil
}

func cleanupIncomplete(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("coreupdate: list core root for cleanup: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, tempDownloadPrefix) && !strings.HasPrefix(name, tempStatePrefix) {
			continue
		}
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("coreupdate: inspect incomplete temp file: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("coreupdate: refusing to remove temp-named directory %q", name)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("coreupdate: remove incomplete temp file %q: %w", name, err)
		}
	}
	return nil
}

func validateLeafName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.IsAbs(name) ||
		filepath.VolumeName(name) != "" || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\:`) || strings.ContainsRune(name, 0) ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("%w: %q", ErrInvalidTarget, name)
	}
	if runtime.GOOS == "windows" && windowsReservedName(name) {
		return fmt.Errorf("%w: reserved Windows device name %q", ErrInvalidTarget, name)
	}
	return nil
}

func windowsReservedName(name string) bool {
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

func validateTargetName(name string) error {
	if name == stateFileName || strings.HasPrefix(name, ".coreupdate-") {
		return fmt.Errorf("%w: target name is reserved by coreupdate", ErrInvalidTarget)
	}
	return validateLeafName(name)
}

func safePath(root, name string) (string, error) {
	if err := validateTargetName(name); err != nil {
		return "", err
	}
	return safeLeafPath(root, name)
}

func safeInternalPath(root, name string) (string, error) {
	if err := validateLeafName(name); err != nil {
		return "", err
	}
	return safeLeafPath(root, name)
}

func safeLeafPath(root, name string) (string, error) {
	candidate := filepath.Join(root, name)
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", fmt.Errorf("coreupdate: calculate target path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: target escapes core root", ErrInvalidTarget)
	}
	if !pathsEqual(filepath.Dir(candidate), root) {
		return "", fmt.Errorf("%w: target is not directly inside core root", ErrInvalidTarget)
	}
	return candidate, nil
}

func defaultTargetName(platform string) string {
	if strings.HasPrefix(platform, "windows-") {
		return "frpc.exe"
	}
	return "frpc"
}

func pathsEqual(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
