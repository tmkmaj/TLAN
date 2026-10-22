//go:build windows

package platform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type SystemRunner struct{}

func (SystemRunner) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	output = cleanPowerShellOutput(output)
	if err != nil {
		errorOutput := cleanPowerShellOutput(stderr.Bytes())
		if len(errorOutput) > 0 {
			output = append(output, errorOutput...)
		}
		return output, fmt.Errorf("%s %v: %w: %s", filepath.Base(name), args, err, output)
	}
	return output, nil
}

// PowerShell may emit CLIXML progress records on stderr when output is
// redirected. Those records are not command data and must never be parsed as
// adapter/rule identities. stdout is used on success; stderr is retained only
// for real failures after this filter.
func cleanPowerShellOutput(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" {
			continue
		}
		if trimmed == "#< CLIXML" || strings.HasPrefix(trimmed, "<Objs") || trimmed == "</Objs>" || strings.Contains(trimmed, `<S S="progress"`) {
			continue
		}
		filtered = append(filtered, strings.TrimSuffix(line, "\r"))
	}
	if len(filtered) == 0 {
		return nil
	}
	return []byte(strings.Join(filtered, "\n") + "\n")
}

func systemPowerShell() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}
