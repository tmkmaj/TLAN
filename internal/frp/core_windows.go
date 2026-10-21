//go:build windows

package frp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const FRPCSHA256 = "509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB"

type Core struct {
	Path    string
	Version string
	SHA256  string
}

func ResolveCore(executableDir string) (Core, error) {
	candidates := []string{}
	add := func(root, relative string) {
		if root != "" {
			candidates = append(candidates, filepath.Join(root, filepath.FromSlash(relative)))
		}
	}
	add(executableDir, "runtime/frp/0.71.1/windows-amd64/frpc.exe")
	add(executableDir, "assets/frp/windows-amd64/frpc.exe")
	add(executableDir, "frpc.exe")
	if cwd, err := os.Getwd(); err == nil {
		add(cwd, "runtime/frp/0.71.1/windows-amd64/frpc.exe")
		add(cwd, "assets/frp/windows-amd64/frpc.exe")
		add(cwd, ".tmp-runtime/frpc-v0.71.1.exe")
	}
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, ok := seen[absolute]; ok {
			continue
		}
		seen[absolute] = struct{}{}
		info, err := os.Stat(absolute)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		sum, err := fileSHA256(absolute)
		if err != nil {
			continue
		}
		if strings.EqualFold(sum, FRPCSHA256) {
			return Core{Path: absolute, Version: CoreVersion, SHA256: sum}, nil
		}
	}
	return Core{}, codedError(CodeCoreInvalid, "bundled frpc %s is missing or its SHA-256 does not match %s", CoreVersion, FRPCSHA256)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil))), nil
}
