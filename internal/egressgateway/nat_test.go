package egressgateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type commandCall struct {
	name string
	args []string
}

type fakeCommandRunner struct {
	mu      sync.Mutex
	calls   []commandCall
	handler func(name string, args []string) error
}

func (r *fakeCommandRunner) Run(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	r.mu.Unlock()
	if r.handler != nil {
		return r.handler(name, args)
	}
	return nil
}

func (r *fakeCommandRunner) Calls() []commandCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]commandCall, len(r.calls))
	copy(out, r.calls)
	return out
}

func (r *fakeCommandRunner) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func defaultNATHandler(name string, args []string) error {
	switch {
	case name == "nft" && slices.Equal(args, []string{"--version"}):
		return nil
	case name == "iptables" && slices.Equal(args, []string{"--version"}):
		return errors.New("iptables not installed")
	case name == "ip" && slices.Equal(args, []string{"link", "show", "dev", "eth0"}):
		return nil
	default:
		return nil
	}
}

func newNATTestManager(t *testing.T, handler func(string, []string) error) (*NatManager, *fakeCommandRunner, string) {
	t.Helper()
	forwardPath := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(forwardPath, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("write forward fixture: %v", err)
	}
	runner := &fakeCommandRunner{handler: handler}
	manager, err := newNATManager(NATConfig{
		EgressInterface: "eth0",
		SourceCIDR:      "10.0.0.0/24",
		IPForwardPath:   forwardPath,
		Marker:          defaultNATMarker,
		NFTTable:        defaultNFTTable,
		IPTablesChain:   defaultIPTablesChain,
	}, runner, true)
	if err != nil {
		t.Fatalf("newNATManager: %v", err)
	}
	return manager, runner, forwardPath
}

func TestNatManagerPlanIsDryRun(t *testing.T) {
	manager, runner, forwardPath := newNATTestManager(t, defaultNATHandler)
	plan, err := manager.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, expected := range []string{"backend: nftables", defaultNATMarker, "ip saddr 10.0.0.0/24", "ip_forward:"} {
		if !strings.Contains(plan, expected) {
			t.Fatalf("plan missing %q:\n%s", expected, plan)
		}
	}
	forward, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatalf("read forward: %v", err)
	}
	if string(forward) != "0\n" {
		t.Fatalf("plan changed forward state to %q", forward)
	}
	for _, call := range runner.Calls() {
		if call.name == "nft" && len(call.args) > 0 && call.args[0] != "--version" {
			t.Fatalf("plan ran mutating nft command: %v", call)
		}
	}
}

func TestNatManagerNftablesApplyAndRollback(t *testing.T) {
	manager, runner, forwardPath := newNATTestManager(t, defaultNATHandler)
	ctx := context.Background()
	if err := manager.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !manager.Applied() {
		t.Fatal("manager not marked applied")
	}
	forward, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatalf("read forward: %v", err)
	}
	if string(forward) != "1" {
		t.Fatalf("forward = %q, want 1", forward)
	}

	countAfterApply := runner.Count()
	if err := manager.Apply(ctx); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if got := runner.Count(); got != countAfterApply {
		t.Fatalf("second Apply executed %d extra commands", got-countAfterApply)
	}

	if err := manager.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	restored, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatalf("read restored forward: %v", err)
	}
	if string(restored) != "0\n" {
		t.Fatalf("restored forward = %q, want original %q", restored, "0\n")
	}
	if manager.Applied() {
		t.Fatal("manager still marked applied")
	}
	countAfterRollback := runner.Count()
	if err := manager.Rollback(ctx); err != nil {
		t.Fatalf("second Rollback: %v", err)
	}
	if got := runner.Count(); got != countAfterRollback {
		t.Fatalf("second Rollback executed %d extra commands", got-countAfterRollback)
	}

	calls := runner.Calls()
	foundOwnDelete := false
	for _, call := range calls {
		if call.name == "nft" && slices.Equal(call.args, []string{"delete", "table", "inet", defaultNFTTable}) {
			foundOwnDelete = true
		}
		if call.name == "nft" && slices.Contains(call.args, "flush") {
			t.Fatalf("nft flush command was used: %v", call)
		}
		if call.name == "nft" && slices.Contains(call.args, "rule") && call.args[0] == "add" {
			if !slices.Contains(call.args, defaultNATMarker) {
				t.Fatalf("nft rule missing product marker: %v", call)
			}
		}
	}
	if !foundOwnDelete {
		t.Fatal("rollback did not delete the dedicated product nft table")
	}
}

func TestNatManagerIPTablesFallback(t *testing.T) {
	handler := func(name string, args []string) error {
		switch {
		case name == "nft" && slices.Equal(args, []string{"--version"}):
			return errors.New("nft not installed")
		case name == "iptables" && slices.Equal(args, []string{"--version"}):
			return nil
		case name == "ip":
			return nil
		default:
			return nil
		}
	}
	manager, runner, forwardPath := newNATTestManager(t, handler)
	ctx := context.Background()
	caps, err := manager.DetectCapabilities(ctx)
	if err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	if caps.Backend != NATBackendIPTables || caps.NFTables || !caps.IPTables {
		t.Fatalf("unexpected capabilities: %+v", caps)
	}
	if err := manager.Apply(ctx); err != nil {
		t.Fatalf("Apply fallback: %v", err)
	}
	insertSeen := false
	for _, call := range runner.Calls() {
		if call.name != "iptables" || slices.Equal(call.args, []string{"--version"}) {
			continue
		}
		mutatesRule := slices.Contains(call.args, "-A") || slices.Contains(call.args, "-I") || (slices.Contains(call.args, "-D") && slices.Contains(call.args, "POSTROUTING"))
		if mutatesRule && !slices.Contains(call.args, defaultNATMarker) {
			t.Fatalf("iptables command missing product marker: %v", call)
		}
		if slices.Contains(call.args, "-F") {
			index := slices.Index(call.args, "-F")
			if index+1 >= len(call.args) || call.args[index+1] != defaultIPTablesChain {
				t.Fatalf("iptables flushed an unrelated chain: %v", call)
			}
		}
		if slices.Contains(call.args, "-I") {
			insertSeen = true
			first := slices.Index(call.args, "POSTROUTING")
			if first < 0 || first+2 >= len(call.args) || call.args[first+2] != "-m" {
				t.Fatalf("malformed iptables insert: %v", call)
			}
		}
	}
	if !insertSeen {
		t.Fatal("iptables jump was not inserted")
	}
	if err := manager.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	forward, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatalf("read forward: %v", err)
	}
	if string(forward) != "0\n" {
		t.Fatalf("forward restored to %q", forward)
	}
	for _, call := range runner.Calls() {
		if call.name == "iptables" && slices.Contains(call.args, "-X") {
			index := slices.Index(call.args, "-X")
			if index+1 >= len(call.args) || call.args[index+1] != defaultIPTablesChain {
				t.Fatalf("iptables deleted an unrelated chain: %v", call)
			}
		}
	}
}

func TestNatManagerMissingBackendAndInterface(t *testing.T) {
	missingBackend := func(name string, args []string) error {
		if slices.Equal(args, []string{"--version"}) {
			return errors.New("not installed")
		}
		return nil
	}
	manager, _, forwardPath := newNATTestManager(t, missingBackend)
	ctx := context.Background()
	if _, err := manager.DetectCapabilities(ctx); !errors.Is(err, ErrNATUnavailable) {
		t.Fatalf("missing backend error = %v", err)
	}
	if err := manager.Apply(ctx); !errors.Is(err, ErrNATUnavailable) {
		t.Fatalf("missing backend Apply error = %v", err)
	}
	forward, _ := os.ReadFile(forwardPath)
	if string(forward) != "0\n" {
		t.Fatalf("missing backend changed forward: %q", forward)
	}

	missingInterface := func(name string, args []string) error {
		switch {
		case name == "nft" && slices.Equal(args, []string{"--version"}):
			return nil
		case name == "iptables" && slices.Equal(args, []string{"--version"}):
			return errors.New("missing")
		case name == "ip":
			return errors.New("device does not exist")
		default:
			return nil
		}
	}
	manager, _, forwardPath = newNATTestManager(t, missingInterface)
	if err := manager.Apply(ctx); !errors.Is(err, ErrNATInterfaceNotFound) {
		t.Fatalf("missing interface error = %v", err)
	}
	forward, _ = os.ReadFile(forwardPath)
	if string(forward) != "0\n" {
		t.Fatalf("missing interface changed forward: %q", forward)
	}
}

func TestNatManagerPartialFailureRollsBack(t *testing.T) {
	handler := func(name string, args []string) error {
		if name == "nft" && len(args) > 0 && args[0] == "add" && slices.Contains(args, "rule") {
			return errors.New("rule rejected")
		}
		return defaultNATHandler(name, args)
	}
	manager, runner, forwardPath := newNATTestManager(t, handler)
	if err := manager.Apply(context.Background()); err == nil {
		t.Fatal("Apply unexpectedly succeeded")
	}
	if manager.Applied() {
		t.Fatal("failed Apply left manager in applied state")
	}
	forward, _ := os.ReadFile(forwardPath)
	if string(forward) != "0\n" {
		t.Fatalf("failed Apply changed forward: %q", forward)
	}
	foundRollback := false
	for _, call := range runner.Calls() {
		if call.name == "nft" && slices.Equal(call.args, []string{"delete", "table", "inet", defaultNFTTable}) {
			foundRollback = true
		}
	}
	if !foundRollback {
		t.Fatal("partial failure did not remove the product table")
	}
}

func TestNatManagerRejectsInvalidConfigAndUnsupportedPlatform(t *testing.T) {
	runner := &fakeCommandRunner{handler: defaultNATHandler}
	invalidConfigs := []NATConfig{
		{EgressInterface: "eth0", SourceCIDR: "not-a-cidr"},
		{EgressInterface: "eth0", SourceCIDR: "0.0.0.0/0"},
		{EgressInterface: "bad/interface", SourceCIDR: "10.0.0.0/24"},
		{EgressInterface: "", SourceCIDR: "10.0.0.0/24"},
	}
	for _, config := range invalidConfigs {
		if _, err := NewNATManager(config, runner); !errors.Is(err, ErrInvalidNATConfig) {
			t.Fatalf("config %+v error = %v", config, err)
		}
	}

	manager, err := newNATManager(NATConfig{EgressInterface: "eth0", SourceCIDR: "10.0.0.0/24"}, runner, false)
	if err != nil {
		t.Fatalf("unsupported manager: %v", err)
	}
	if _, err := manager.DetectCapabilities(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DetectCapabilities unsupported error = %v", err)
	}
	if err := manager.Apply(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Apply unsupported error = %v", err)
	}
	if _, err := manager.Plan(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Plan unsupported error = %v", err)
	}
}

func TestNatManagerRollbackWithoutApplyIsNoOp(t *testing.T) {
	manager, runner, _ := newNATTestManager(t, defaultNATHandler)
	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback without Apply: %v", err)
	}
	if got := runner.Count(); got != 0 {
		t.Fatalf("rollback without apply ran %d commands", got)
	}
}
