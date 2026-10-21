//go:build windows

package frp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countingLeaseProvider struct {
	calls int
	err   error
}

func (p *countingLeaseProvider) Acquire(context.Context, LeaseRequest) (Lease, error) {
	p.calls++
	if p.err != nil {
		return Lease{}, p.err
	}
	return Lease{}, errors.New("unexpected lease acquisition")
}

func (p *countingLeaseProvider) Renew(context.Context, string) (Lease, error) {
	return Lease{}, errors.New("unexpected lease renewal")
}

func (p *countingLeaseProvider) Release(context.Context, string) error { return nil }

func secretBackedCeilingConfig(t *testing.T) Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "private_token"
	cfg.Profile.Rules = []Rule{
		{
			ID: "rule-secret", Name: "Secret-backed TCP", Type: "tcp", Enabled: true, SecretRef: "rule-secret",
			Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
			Exposure: Exposure{RemotePort: 30001, AllowUsers: []string{"alice", "bob"}},
		},
		{
			ID: "rule-http", Name: "HTTP password", Type: "http", Enabled: true, Exposure: Exposure{
				CustomDomains: []string{"app.example.test"}, HTTPPasswordRef: "http-secret", HTTPUser: "alice",
			},
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8081},
		},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-secret", Name: "Visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-service", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 19001,
	}}
	return cfg
}

func TestRuntimeCeilingPreservesSecretReferences(t *testing.T) {
	cfg := secretBackedCeilingConfig(t)
	ceiling := CloneConfig(cfg)
	manager := &Manager{runtimeCeiling: &ceiling}

	limited, err := manager.limitToRuntimeCeiling(cfg)
	if err != nil {
		t.Fatalf("recovery with secret-backed permissions failed: %v", err)
	}
	if len(limited.Profile.Rules) != 2 || len(limited.Profile.Visitors) != 1 {
		t.Fatalf("secret-backed permissions were dropped: rules=%+v visitors=%+v", limited.Profile.Rules, limited.Profile.Visitors)
	}

	deleted := CloneConfig(cfg)
	deleted.Profile.Rules = deleted.Profile.Rules[:1]
	deleted.Profile.Visitors = nil
	limited, fullyAllowed := previousAllowedByCeiling(cfg, deleted)
	if fullyAllowed || len(limited.Profile.Rules) != 1 || len(limited.Profile.Visitors) != 0 {
		t.Fatalf("deleted permissions were not intersected correctly: fully=%v rules=%+v visitors=%+v", fullyAllowed, limited.Profile.Rules, limited.Profile.Visitors)
	}

	tightened := CloneConfig(cfg)
	tightened.Profile.Rules[0].Exposure.RemotePort = 30002
	limited, fullyAllowed = previousAllowedByCeiling(cfg, tightened)
	if fullyAllowed {
		t.Fatal("tightened port was treated as fully reversible")
	}
	for _, rule := range limited.Profile.Rules {
		if rule.ID == "rule-secret" {
			t.Fatal("tightened secret-backed rule was incorrectly restored")
		}
	}

	tightenedUsers := CloneConfig(cfg)
	tightenedUsers.Profile.Rules[0].Exposure.AllowUsers = []string{"alice"}
	limited, fullyAllowed = previousAllowedByCeiling(cfg, tightenedUsers)
	if fullyAllowed {
		t.Fatal("tightened allowUsers was treated as fully reversible")
	}
	for _, rule := range limited.Profile.Rules {
		if rule.ID == "rule-secret" {
			t.Fatal("allowUsers-tightened rule was incorrectly restored")
		}
	}
}

func TestRuntimeCeilingPersistenceFailureFailsClosedBeforeRestore(t *testing.T) {
	root := t.TempDir()
	blockingPath := filepath.Join(root, runtimeCeilingFileName)
	if err := os.MkdirAll(blockingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockingPath, "block"), []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}

	previous := testConfig(t)
	previous.Profile.Server.Kind = "managed"
	previous.Profile.Server.ServerID = "frps-test"
	previous.Profile.Rules[0].SecretRef = "rule-secret"
	next := CloneConfig(previous)
	next.Profile.Rules = nil
	secrets := map[string]string{"rule-secret": "plain-secret"}
	provider := &countingLeaseProvider{err: errors.New("must not acquire")}
	manager := &Manager{store: store, leaseProvider: provider, state: "running"}
	manager.desiredRun.Store(true)

	err = manager.restoreAfterApplyFailure(context.Background(), previous, next, "token", "token", secrets, secrets, errors.New("apply failed"))
	if err == nil || !strings.Contains(err.Error(), "撤销意图持久化失败") {
		t.Fatalf("expected fail-closed ceiling error, got %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("restore attempted to acquire a lease after ceiling persistence failed: %d", provider.calls)
	}
	if manager.desiredRun.Load() {
		t.Fatal("failed ceiling persistence retained run intent")
	}
	manager.mu.Lock()
	state := manager.state
	instance := manager.instance
	lastErr := manager.lastErr
	manager.mu.Unlock()
	if state != "failed" || instance != nil || lastErr == nil {
		t.Fatalf("fail-closed state = state:%s instance:%v lastErr:%v", state, instance, lastErr)
	}

	if err = manager.setRuntimeCeiling(nil); err == nil {
		t.Fatal("ceiling removal unexpectedly succeeded with a blocking directory")
	}
	if _, err = manager.limitToRuntimeCeiling(previous); err == nil || !strings.Contains(err.Error(), "未保存成功") {
		t.Fatalf("failed ceiling removal did not remain fail-closed: %v", err)
	}
}

func TestProcessExitCallbackCannotOverwriteNewInstance(t *testing.T) {
	old := &managedInstance{generation: 1}
	current := &managedInstance{generation: 2}
	manager := &Manager{state: "running", instance: current, instanceGeneration: current.generation}
	manager.desiredRun.Store(true)

	manager.handleProcessExit(old, errors.New("old process failed"), errors.New("old cleanup failed"), nil)
	manager.mu.Lock()
	state := manager.state
	lastErr := manager.lastErr
	active := manager.instance
	manager.mu.Unlock()
	if state != "running" || lastErr != nil || active != current || !manager.desiredRun.Load() {
		t.Fatalf("stale process exit overwrote current runtime: state=%s lastErr=%v active=%p desired=%v", state, lastErr, active, manager.desiredRun.Load())
	}

	manager.handleProcessExit(current, errors.New("current process failed"), nil, nil)
	manager.mu.Lock()
	state = manager.state
	lastErr = manager.lastErr
	active = manager.instance
	manager.mu.Unlock()
	if state != "failed" || lastErr == nil || active != nil || manager.desiredRun.Load() {
		t.Fatalf("current process exit was not recorded: state=%s lastErr=%v active=%p desired=%v", state, lastErr, active, manager.desiredRun.Load())
	}
}

func TestCleanupErrorsAreJoinedWithoutHidingPrimaryError(t *testing.T) {
	cause := codedError(CodeProcessFailed, "start failed")
	err := withCleanupErrors(cause, errors.New("remove runtime directory failed"))
	if ErrorCode(err) != CodeProcessFailed {
		t.Fatalf("primary error code = %s, want %s: %v", ErrorCode(err), CodeProcessFailed, err)
	}
	if !strings.Contains(err.Error(), "remove runtime directory failed") || !strings.Contains(err.Error(), "start failed") {
		t.Fatalf("joined cleanup error lost detail: %v", err)
	}
}
