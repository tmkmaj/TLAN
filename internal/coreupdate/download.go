package coreupdate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type downloadResult struct {
	path   string
	size   int64
	sha256 string
}

func (i *Installer) download(ctx context.Context, manifest Manifest) (downloadResult, error) {
	client, err := i.httpClientFor(manifest.URL)
	if err != nil {
		return downloadResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.URL, nil)
	if err != nil {
		return downloadResult{}, fmt.Errorf("coreupdate: create download request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return downloadResult{}, fmt.Errorf("coreupdate: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil {
		initial, _ := url.Parse(manifest.URL)
		if !sameOrigin(initial, resp.Request.URL) {
			return downloadResult{}, ErrCrossHostRedirect
		}
	}
	if resp.StatusCode != http.StatusOK {
		return downloadResult{}, fmt.Errorf("coreupdate: download returned HTTP %d", resp.StatusCode)
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return downloadResult{}, fmt.Errorf("coreupdate: unsupported Content-Encoding %q", encoding)
	}
	if resp.ContentLength > i.maxDownloadBytes {
		return downloadResult{}, fmt.Errorf("%w: Content-Length %d", ErrDownloadTooLarge, resp.ContentLength)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != manifest.Size {
		return downloadResult{}, fmt.Errorf("%w: Content-Length %d, manifest %d", ErrDownloadSizeMismatch, resp.ContentLength, manifest.Size)
	}

	f, err := os.CreateTemp(i.root, tempDownloadPrefix+"*")
	if err != nil {
		return downloadResult{}, fmt.Errorf("coreupdate: create download temp file: %w", err)
	}
	path := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return downloadResult{}, err
	}
	if manifest.Size == int64(^uint64(0)>>1) {
		return downloadResult{}, fmt.Errorf("%w: size overflow", ErrDownloadTooLarge)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, manifest.Size+1))
	if err != nil {
		return downloadResult{}, fmt.Errorf("coreupdate: read download body: %w", err)
	}
	if n != manifest.Size {
		return downloadResult{}, fmt.Errorf("%w: read %d bytes, want %d", ErrDownloadSizeMismatch, n, manifest.Size)
	}
	if err := f.Sync(); err != nil {
		return downloadResult{}, err
	}
	if err := f.Close(); err != nil {
		return downloadResult{}, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(manifest.SHA256)) != 1 {
		return downloadResult{}, ErrHashMismatch
	}
	if err := verifyFileHash(path, manifest.SHA256, manifest.Size); err != nil {
		return downloadResult{}, err
	}
	if err := secureFile(path, 0o700); err != nil {
		return downloadResult{}, err
	}
	keep = true
	return downloadResult{path: path, size: n, sha256: got}, nil
}

func (i *Installer) httpClientFor(raw string) (*http.Client, error) {
	initial, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPSRequired, err)
	}
	if initial.Scheme != "https" || initial.Hostname() == "" {
		return nil, ErrHTTPSRequired
	}
	var base http.Client
	if i.httpClient != nil {
		base = *i.httpClient
	}
	if base.Timeout <= 0 {
		base.Timeout = 2 * time.Minute
	}
	originalCheck := base.CheckRedirect
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("coreupdate: stopped after 10 redirects")
		}
		if req.URL.Scheme != "https" || req.URL.User != nil {
			return ErrHTTPSRequired
		}
		if len(via) == 0 || !sameOrigin(via[0].URL, req.URL) {
			return ErrCrossHostRedirect
		}
		if originalCheck != nil {
			return originalCheck(req, via)
		}
		return nil
	}
	return &base, nil
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || a.Scheme != "https" || b.Scheme != "https" {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}
