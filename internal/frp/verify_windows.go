//go:build windows

package frp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

func verifyFRPC(ctx context.Context, corePath, configPath, workingDir string, extraEnv map[string]string) (retErr error) {
	verifyCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	launched, err := launchRestrictedArgs(corePath, []string{"verify", "-c", configPath, "--strict_config=true"}, workingDir, extraEnv)
	if err != nil {
		if errors.Is(verifyCtx.Err(), context.DeadlineExceeded) {
			return codedError(CodeConfigurationInvalid, "frpc verify timed out")
		}
		if verifyCtx.Err() != nil {
			return codedError(CodeProcessFailed, "frpc verify canceled before restricted launch: %v", verifyCtx.Err())
		}
		return codedError(CodeProcessFailed, "frpc verify could not start with a restricted token: %v", err)
	}
	defer func() {
		retErr = withCleanupErrors(retErr, closeHandlesErr(launched.Process, launched.Job))
	}()

	closeHandles(launched.Stdin)
	launched.Stdin = 0
	stdoutFile := os.NewFile(uintptr(launched.Stdout), "frpc-verify-stdout")
	stderrFile := os.NewFile(uintptr(launched.Stderr), "frpc-verify-stderr")
	launched.Stdout = 0
	launched.Stderr = 0
	if stdoutFile == nil || stderrFile == nil {
		if stdoutFile != nil {
			_ = stdoutFile.Close()
		}
		if stderrFile != nil {
			_ = stderrFile.Close()
		}
		return codedError(CodeProcessFailed, "frpc verify could not open restricted process output pipes")
	}

	var output limitedBuffer
	output.limit = 128 * 1024
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		defer stdoutFile.Close()
		_, _ = io.Copy(&output, stdoutFile)
	}()
	go func() {
		defer readers.Done()
		defer stderrFile.Close()
		_, _ = io.Copy(&output, stderrFile)
	}()

	type waitResult struct {
		code uint32
		err  error
	}
	waitCh := make(chan waitResult, 1)
	go func() {
		code, err := waitProcess(launched.Process)
		waitCh <- waitResult{code: code, err: err}
	}()

	select {
	case result := <-waitCh:
		readers.Wait()
		if result.err != nil {
			return codedError(CodeProcessFailed, "frpc verify wait failed: %v", result.err)
		}
		message := strings.TrimSpace(output.String())
		if result.code != 0 {
			if message == "" {
				message = fmt.Sprintf("frpc verify exited with status %#x", result.code)
			}
			return classifyStartupError(message)
		}
		if !strings.Contains(output.String(), "syntax is ok") {
			return codedError(CodeConfigurationInvalid, "frpc verify did not confirm a valid configuration: %s", message)
		}
		return nil
	case <-verifyCtx.Done():
		terminateErr := windows.TerminateJobObject(launched.Job, 1)
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		var waitCleanupErr error
		select {
		case <-waitCh:
		case <-time.After(3 * time.Second):
			waitCleanupErr = fmt.Errorf("restricted frpc verify process did not exit after termination")
		}
		readers.Wait()
		cleanupErr := errors.Join(terminateErr, waitCleanupErr)
		if errors.Is(verifyCtx.Err(), context.DeadlineExceeded) {
			return withCleanupErrors(codedError(CodeConfigurationInvalid, "frpc verify timed out"), cleanupErr)
		}
		return withCleanupErrors(codedError(CodeProcessFailed, "frpc verify canceled: %v", verifyCtx.Err()), cleanupErr)
	}
}

type limitedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
