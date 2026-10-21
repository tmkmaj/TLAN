package coreupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInstallHappyPath(t *testing.T) {
	body := []byte("signed-frpc-v1")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	manifest := testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body)
	data := signedTestManifest(t, manifest, privateKey)
	result, err := installer.Install(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Committed || result.Version != "1.1.0" || result.SHA256 != manifest.SHA256 {
		t.Fatalf("unexpected result: %+v", result)
	}
	got, err := os.ReadFile(filepath.Join(root, "frpc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("installed body = %q, want %q", got, body)
	}
	state, _, exists, err := loadState(filepath.Join(root, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !exists || state.Version != "1.1.0" || state.TargetName != "frpc-test" {
		t.Fatalf("unexpected state: %+v exists=%v", state, exists)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempDownloadPrefix) || strings.HasPrefix(entry.Name(), tempStatePrefix) {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("core root mode = %o, want 700", info.Mode().Perm())
		}
	}
}

func TestInstallRejectsUnmanagedTarget(t *testing.T) {
	body := []byte("new")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "frpc-test"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	_, err := installer.Install(context.Background(), data)
	if !errors.Is(err, ErrUnmanagedTarget) {
		t.Fatalf("unmanaged target error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "frpc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "foreign" {
		t.Fatalf("foreign target changed to %q", got)
	}
}

func TestInstallRejectsTargetTraversal(t *testing.T) {
	root := t.TempDir()
	publicKey, _ := newTestKeyPair(t)
	_, err := NewInstaller(Config{
		CoreRoot:         root,
		PublicKey:        publicKey,
		CurrentVersion:   "1.0.0",
		Platform:         "windows-amd64",
		AllowedVersions:  []string{"1.1.0"},
		AllowedPlatforms: []string{"windows-amd64"},
		TargetName:       "../frpc.exe",
	})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("traversal error = %v", err)
	}
}

func TestInstallRejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(root, "frpc-test")
	outsideFile := filepath.Join(outside, "outside")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	body := []byte("new")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink target error = %v", err)
	}
}

func TestInstallRejectsTamperedArtifactHash(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("evil"))
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", []byte("good")), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered artifact error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "frpc-test")); !os.IsNotExist(err) {
		t.Fatalf("target should not exist after hash failure: %v", err)
	}
}

func TestInstallInterruptedDownload(t *testing.T) {
	body := []byte("good")
	publicKey, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc", body)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          &failingBody{data: body[:2]},
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	})}
	root := t.TempDir()
	installer := newTestInstaller(t, root, publicKey, client, "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, manifest, privateKey)
	if _, err := installer.Install(context.Background(), data); err == nil {
		t.Fatal("expected interrupted download error")
	}
	if _, err := os.Stat(filepath.Join(root, "frpc-test")); !os.IsNotExist(err) {
		t.Fatalf("target should not exist after interrupted download: %v", err)
	}
}

func TestInstallRejectsOversizedManifest(t *testing.T) {
	body := []byte("1234567890")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	installer.maxDownloadBytes = 3
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("oversized manifest error = %v", err)
	}
}

func TestInstallRejectsCrossHostRedirect(t *testing.T) {
	body := []byte("new")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/frpc", http.StatusFound)
	}))
	defer redirect.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, redirect.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", redirect.URL+"/frpc", body), privateKey)
	_, err := installer.Install(context.Background(), data)
	if !errors.Is(err, ErrCrossHostRedirect) {
		t.Fatalf("cross-host redirect error = %v", err)
	}
}

func TestAtomicReplaceFailureLeavesNoTarget(t *testing.T) {
	body := []byte("new")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	installer.atomicReplace = func(src, dst string) error {
		return errors.New("injected atomic replace failure")
	}
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	result, err := installer.Install(context.Background(), data)
	if err == nil || !strings.Contains(err.Error(), "injected atomic replace failure") {
		t.Fatalf("atomic replace error = %v", err)
	}
	if result.Committed {
		t.Fatalf("result should not be committed: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(root, "frpc-test")); !os.IsNotExist(err) {
		t.Fatalf("target should not exist: %v", err)
	}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempDownloadPrefix) {
			t.Fatalf("download temp left behind: %s", entry.Name())
		}
	}
}

func TestRollbackRestoresOldVersionOnStateCommitFailure(t *testing.T) {
	oldBody := []byte("old-version")
	oldServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oldBody)
	}))
	defer oldServer.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	oldInstaller := newTestInstaller(t, root, publicKey, oldServer.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	oldData := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", oldServer.URL+"/frpc", oldBody), privateKey)
	if _, err := oldInstaller.Install(context.Background(), oldData); err != nil {
		t.Fatal(err)
	}

	newBody := []byte("new-version")
	newServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBody)
	}))
	defer newServer.Close()
	installer := newTestInstaller(t, root, publicKey, newServer.Client(), "1.1.0", "1.2.0", "windows-amd64", "frpc-test")
	original := installer.atomicReplace
	calls := 0
	installer.atomicReplace = func(src, dst string) error {
		calls++
		if calls == 2 {
			return errors.New("injected state commit failure")
		}
		return original(src, dst)
	}
	data := signedTestManifest(t, testManifest("1.2.0", "windows-amd64", newServer.URL+"/frpc", newBody), privateKey)
	result, err := installer.Install(context.Background(), data)
	if err == nil || !result.RolledBack {
		t.Fatalf("expected rolled-back error, result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(filepath.Join(root, "frpc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldBody) {
		t.Fatalf("rollback body = %q, want %q", got, oldBody)
	}
	state, _, exists, err := loadState(filepath.Join(root, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !exists || state.Version != "1.1.0" {
		t.Fatalf("rollback state = %+v exists=%v", state, exists)
	}
}

func TestPostInstallVerificationFailureRollsBack(t *testing.T) {
	oldBody := []byte("old-version")
	oldServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oldBody)
	}))
	defer oldServer.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	oldInstaller := newTestInstaller(t, root, publicKey, oldServer.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	oldData := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", oldServer.URL+"/frpc", oldBody), privateKey)
	if _, err := oldInstaller.Install(context.Background(), oldData); err != nil {
		t.Fatal(err)
	}

	newBody := []byte("new-version")
	newServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBody)
	}))
	defer newServer.Close()
	installer := newTestInstaller(t, root, publicKey, newServer.Client(), "1.1.0", "1.2.0", "windows-amd64", "frpc-test")
	original := installer.atomicReplace
	calls := 0
	installer.atomicReplace = func(src, dst string) error {
		calls++
		if err := original(src, dst); err != nil {
			return err
		}
		if calls == 1 {
			return os.WriteFile(dst, []byte("tampered-after-replace"), 0o700)
		}
		return nil
	}
	data := signedTestManifest(t, testManifest("1.2.0", "windows-amd64", newServer.URL+"/frpc", newBody), privateKey)
	result, err := installer.Install(context.Background(), data)
	if err == nil || !result.RolledBack {
		t.Fatalf("expected post-install rollback, result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(filepath.Join(root, "frpc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldBody) {
		t.Fatalf("post-install rollback body = %q, want %q", got, oldBody)
	}
}

func TestInstallCleansIncompleteTempFiles(t *testing.T) {
	body := []byte("new")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, tempDownloadPrefix+"stale"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, tempStatePrefix+"stale"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	if _, err := installer.Install(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{tempDownloadPrefix + "stale", tempStatePrefix + "stale"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("temp file %s still exists: %v", name, err)
		}
	}
}

func TestInstallRejectsCorruptState(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, stateFileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("new")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", body), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("corrupt state error = %v", err)
	}
}

func TestInstallRejectsNonNewerVersion(t *testing.T) {
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer, err := NewInstaller(Config{
		CoreRoot:         root,
		PublicKey:        publicKey,
		CurrentVersion:   "1.1.0",
		Platform:         "windows-amd64",
		AllowedVersions:  []string{"1.1.0"},
		AllowedPlatforms: []string{"windows-amd64"},
		TargetName:       "frpc-test",
		Now:              func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("same")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", "https://example.test/frpc", body), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrVersionNotNewer) {
		t.Fatalf("non-newer version error = %v", err)
	}
}

func TestInstallRejectsArtifactSizeMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/frpc", []byte("1234")), privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrDownloadSizeMismatch) {
		t.Fatalf("artifact size mismatch error = %v", err)
	}
}

func TestDownloadBodyLimitRejectsExtraBytesWithoutContentLength(t *testing.T) {
	body := []byte("good")
	publicKey, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc", body)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("good!")),
			ContentLength: -1,
			Request:       req,
		}, nil
	})}
	root := t.TempDir()
	installer := newTestInstaller(t, root, publicKey, client, "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, manifest, privateKey)
	if _, err := installer.Install(context.Background(), data); !errors.Is(err, ErrDownloadSizeMismatch) {
		t.Fatalf("body limit error = %v", err)
	}
}

func TestPrepareRootRejectsSymlink(t *testing.T) {
	actual := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(actual, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := prepareRoot(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("root symlink error = %v", err)
	}
}

func TestInstallRejectsReservedTargetName(t *testing.T) {
	publicKey, _ := newTestKeyPair(t)
	_, err := NewInstaller(Config{
		CoreRoot:         t.TempDir(),
		PublicKey:        publicKey,
		CurrentVersion:   "1.0.0",
		Platform:         "windows-amd64",
		AllowedVersions:  []string{"1.1.0"},
		AllowedPlatforms: []string{"windows-amd64"},
		TargetName:       stateFileName,
	})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("reserved target error = %v", err)
	}
}

func TestInstallRejectsAmbiguousTargetNames(t *testing.T) {
	publicKey, _ := newTestKeyPair(t)
	targets := []string{"frpc.", "frpc ", "frpc:stream"}
	if runtime.GOOS == "windows" {
		targets = append(targets, "CON")
	}
	for _, target := range targets {
		_, err := NewInstaller(Config{
			CoreRoot:         t.TempDir(),
			PublicKey:        publicKey,
			CurrentVersion:   "1.0.0",
			Platform:         "windows-amd64",
			AllowedVersions:  []string{"1.1.0"},
			AllowedPlatforms: []string{"windows-amd64"},
			TargetName:       target,
		})
		if !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("target %q error = %v", target, err)
		}
	}
}

func TestAtomicReplaceFailureKeepsOldVersion(t *testing.T) {
	oldBody := []byte("old-version")
	oldServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oldBody)
	}))
	defer oldServer.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	oldInstaller := newTestInstaller(t, root, publicKey, oldServer.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	oldData := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", oldServer.URL+"/frpc", oldBody), privateKey)
	if _, err := oldInstaller.Install(context.Background(), oldData); err != nil {
		t.Fatal(err)
	}

	newBody := []byte("new-version")
	newServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBody)
	}))
	defer newServer.Close()
	installer := newTestInstaller(t, root, publicKey, newServer.Client(), "1.1.0", "1.2.0", "windows-amd64", "frpc-test")
	installer.atomicReplace = func(src, dst string) error {
		return errors.New("injected replacement failure")
	}
	data := signedTestManifest(t, testManifest("1.2.0", "windows-amd64", newServer.URL+"/frpc", newBody), privateKey)
	result, err := installer.Install(context.Background(), data)
	if err == nil || !strings.Contains(err.Error(), "injected replacement failure") {
		t.Fatalf("replacement error = %v", err)
	}
	if result.Committed {
		t.Fatalf("result should not be committed: %+v", result)
	}
	got, err := os.ReadFile(filepath.Join(root, "frpc-test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldBody) {
		t.Fatalf("old version changed to %q", got)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempDownloadPrefix) || strings.HasPrefix(entry.Name(), backupPrefix) {
			t.Fatalf("transaction temp file left behind: %s", entry.Name())
		}
	}
}

func TestInstallAllowsSameHostRedirect(t *testing.T) {
	body := []byte("redirected-binary")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/frpc", http.StatusFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	root := t.TempDir()
	publicKey, privateKey := newTestKeyPair(t)
	installer := newTestInstaller(t, root, publicKey, server.Client(), "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", server.URL+"/redirect", body), privateKey)
	if _, err := installer.Install(context.Background(), data); err != nil {
		t.Fatalf("same-host redirect failed: %v", err)
	}
}

func TestInstallRejectsCompressedResponse(t *testing.T) {
	body := []byte("binary")
	publicKey, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc", body)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Encoding", "gzip")
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        header,
			Body:          io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	})}
	root := t.TempDir()
	installer := newTestInstaller(t, root, publicKey, client, "1.0.0", "1.1.0", "windows-amd64", "frpc-test")
	data := signedTestManifest(t, manifest, privateKey)
	if _, err := installer.Install(context.Background(), data); err == nil || !strings.Contains(err.Error(), "Content-Encoding") {
		t.Fatalf("compressed response error = %v", err)
	}
}
