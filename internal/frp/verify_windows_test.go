//go:build windows

package frp

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyFRPCUsesRestrictedProcess(t *testing.T) {
	frpcPath, err := filepath.Abs(filepath.Join("..", "..", "assets", "frp", "windows-amd64", "frpc.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(frpcPath); err != nil {
		t.Skipf("fixed frpc unavailable: %v", err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frpc.toml")
	config := "serverAddr = \"127.0.0.1\"\n" +
		"serverPort = 7000\n" +
		"auth.token = \"test-token\"\n\n" +
		"[[proxies]]\n" +
		"name = \"test\"\n" +
		"type = \"tcp\"\n" +
		"localIP = \"127.0.0.1\"\n" +
		"localPort = 8080\n" +
		"remotePort = 30001\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := verifyFRPC(ctx, frpcPath, configPath, dir, nil); err != nil {
		t.Fatalf("restricted frpc verify failed: %v", err)
	}
}

func TestRestrictedCommandLauncherCapturesOutputAndTokenEvidence(t *testing.T) {
	cmdPath := os.Getenv("ComSpec")
	if cmdPath == "" {
		t.Skip("ComSpec is unavailable")
	}
	launched, err := launchRestrictedArgs(cmdPath, []string{"/d", "/s", "/c", "echo syntax is ok"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandles(launched.Process, launched.Job)
	closeHandles(launched.Stdin)
	stdoutFile := os.NewFile(uintptr(launched.Stdout), "restricted-verify-stdout")
	stderrFile := os.NewFile(uintptr(launched.Stderr), "restricted-verify-stderr")
	if stdoutFile == nil || stderrFile == nil {
		t.Fatal("restricted process output handles are invalid")
	}
	defer stdoutFile.Close()
	defer stderrFile.Close()
	code, waitErr := waitProcess(launched.Process)
	if waitErr != nil {
		t.Fatal(waitErr)
	}
	stdout, _ := io.ReadAll(stdoutFile)
	stderr, _ := io.ReadAll(stderrFile)
	if code != 0 {
		t.Fatalf("restricted command exited %d: stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(string(stdout), "syntax is ok") {
		t.Fatalf("restricted command stdout = %q", stdout)
	}
	if launched.Token.AdminGroup == "enabled" || launched.Token.IntegrityLevel == "High" {
		t.Fatalf("restricted launch inherited administrator token evidence: %+v", launched.Token)
	}
}
