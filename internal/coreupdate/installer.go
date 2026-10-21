package coreupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultMaxDownloadBytes caps a core artifact by default.
	DefaultMaxDownloadBytes int64 = 64 << 20
)

// Config describes one update target. PublicKey, CurrentVersion, Platform,
// AllowedVersions, and AllowedPlatforms must be supplied by the caller.
type Config struct {
	CoreRoot         string
	PublicKey        ed25519.PublicKey
	CurrentVersion   string
	Platform         string
	AllowedVersions  []string
	AllowedPlatforms []string
	TargetName       string
	MaxManifestBytes int64
	MaxDownloadBytes int64
	HTTPClient       *http.Client
	Now              func() time.Time
	ClockSkew        time.Duration
}

// Installer installs signed core artifacts into one caller-selected root.
type Installer struct {
	root             string
	publicKey        ed25519.PublicKey
	currentVersion   string
	platform         string
	allowedVersions  []string
	allowedPlatforms []string
	targetName       string
	maxManifestBytes int64
	maxDownloadBytes int64
	httpClient       *http.Client
	now              func() time.Time
	clockSkew        time.Duration
	atomicReplace    func(string, string) error
}

// Result reports the outcome of an install transaction.
type Result struct {
	Version    string
	Platform   string
	TargetPath string
	SHA256     string
	Size       int64
	Committed  bool
	RolledBack bool
	Warnings   []string
}

// NewInstaller validates all fail-closed policy inputs and returns an installer.
func NewInstaller(cfg Config) (*Installer, error) {
	if cfg.CoreRoot == "" {
		return nil, fmt.Errorf("%w: core root is empty", ErrInvalidTarget)
	}
	if len(cfg.PublicKey) == 0 {
		return nil, ErrNoPublicKey
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	if cfg.CurrentVersion == "" {
		return nil, fmt.Errorf("%w: current version is empty", ErrInvalidManifest)
	}
	if _, err := parseVersion(cfg.CurrentVersion); err != nil {
		return nil, fmt.Errorf("%w: invalid current version", ErrInvalidManifest)
	}
	if !platformPattern.MatchString(cfg.Platform) {
		return nil, fmt.Errorf("%w: invalid target platform", ErrPlatformNotAllowed)
	}
	if len(cfg.AllowedVersions) == 0 {
		return nil, fmt.Errorf("%w: version whitelist is empty", ErrVersionNotAllowed)
	}
	for _, version := range cfg.AllowedVersions {
		if _, err := parseVersion(version); err != nil {
			return nil, fmt.Errorf("%w: invalid allowed version", ErrVersionNotAllowed)
		}
	}
	if len(cfg.AllowedPlatforms) == 0 {
		return nil, fmt.Errorf("%w: platform whitelist is empty", ErrPlatformNotAllowed)
	}
	platformFound := false
	for _, platform := range cfg.AllowedPlatforms {
		if !platformPattern.MatchString(platform) {
			return nil, fmt.Errorf("%w: invalid allowed platform", ErrPlatformNotAllowed)
		}
		if platform == cfg.Platform {
			platformFound = true
		}
	}
	if !platformFound {
		return nil, fmt.Errorf("%w: target platform %s is not whitelisted", ErrPlatformNotAllowed, cfg.Platform)
	}
	targetName := cfg.TargetName
	if targetName == "" {
		targetName = defaultTargetName(cfg.Platform)
	}
	if err := validateTargetName(targetName); err != nil {
		return nil, err
	}
	if cfg.MaxManifestBytes < 0 || cfg.MaxDownloadBytes < 0 {
		return nil, fmt.Errorf("coreupdate: size limits cannot be negative")
	}
	maxManifest := cfg.MaxManifestBytes
	if maxManifest == 0 {
		maxManifest = DefaultMaxManifestBytes
	}
	maxDownload := cfg.MaxDownloadBytes
	if maxDownload == 0 {
		maxDownload = DefaultMaxDownloadBytes
	}
	if cfg.ClockSkew < 0 {
		return nil, fmt.Errorf("coreupdate: clock skew cannot be negative")
	}
	clockSkew := cfg.ClockSkew
	if clockSkew == 0 {
		clockSkew = 5 * time.Minute
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Installer{
		root:             filepath.Clean(cfg.CoreRoot),
		publicKey:        append(ed25519.PublicKey(nil), cfg.PublicKey...),
		currentVersion:   cfg.CurrentVersion,
		platform:         cfg.Platform,
		allowedVersions:  append([]string(nil), cfg.AllowedVersions...),
		allowedPlatforms: append([]string(nil), cfg.AllowedPlatforms...),
		targetName:       targetName,
		maxManifestBytes: maxManifest,
		maxDownloadBytes: maxDownload,
		httpClient:       cfg.HTTPClient,
		now:              now,
		clockSkew:        clockSkew,
		atomicReplace:    atomicReplaceFile,
	}, nil
}

// Install verifies, downloads, atomically installs, re-verifies, and commits a
// signed artifact. Any failure after replacement attempts a full rollback.
func (i *Installer) Install(ctx context.Context, manifestData []byte) (Result, error) {
	var result Result
	if i == nil || len(i.publicKey) == 0 {
		return result, ErrNoPublicKey
	}
	if len(i.publicKey) != ed25519.PublicKeySize {
		return result, ErrInvalidPublicKey
	}
	if i.atomicReplace == nil {
		return result, errors.New("coreupdate: installer has no atomic replace implementation")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := prepareRoot(i.root)
	if err != nil {
		return result, err
	}
	if err := cleanupIncomplete(root); err != nil {
		return result, err
	}
	now := i.now().UTC()
	opts := i.verifyOptions(now)
	manifest, err := VerifySignedManifest(manifestData, opts)
	if err != nil {
		return result, err
	}
	if manifest.Size > i.maxDownloadBytes {
		return result, fmt.Errorf("%w: manifest size %d > limit %d", ErrDownloadTooLarge, manifest.Size, i.maxDownloadBytes)
	}
	cmp, err := CompareVersions(manifest.Version, i.currentVersion)
	if err != nil {
		return result, err
	}
	if cmp <= 0 {
		return result, fmt.Errorf("%w: manifest %s, current %s", ErrVersionNotNewer, manifest.Version, i.currentVersion)
	}
	targetPath, err := safePath(root, i.targetName)
	if err != nil {
		return result, err
	}
	statePath, err := safeInternalPath(root, stateFileName)
	if err != nil {
		return result, err
	}
	oldState, oldStateBytes, oldStateExists, err := loadState(statePath)
	if err != nil {
		return result, err
	}
	if oldStateExists {
		if oldState.TargetName != i.targetName {
			return result, fmt.Errorf("%w: managed target name changed", ErrStateCorrupt)
		}
		if err := verifyFileHash(targetPath, oldState.SHA256, oldState.Size); err != nil {
			return result, fmt.Errorf("coreupdate: current managed target failed verification: %w", err)
		}
	} else if info, statErr := os.Lstat(targetPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("%w: target is a symbolic link", ErrSymlink)
		}
		return result, ErrUnmanagedTarget
	} else if !os.IsNotExist(statErr) {
		return result, fmt.Errorf("coreupdate: inspect target: %w", statErr)
	}

	downloaded, err := i.download(ctx, manifest)
	if err != nil {
		return result, err
	}
	downloadConsumed := false
	defer func() {
		if !downloadConsumed {
			_ = removeIfExists(downloaded.path)
		}
	}()
	if _, err := VerifySignedManifest(manifestData, opts); err != nil {
		return result, fmt.Errorf("coreupdate: manifest re-verification failed: %w", err)
	}
	if downloaded.sha256 != manifest.SHA256 || downloaded.size != manifest.Size {
		return result, ErrHashMismatch
	}
	if oldStateExists {
		if err := verifyFileHash(targetPath, oldState.SHA256, oldState.Size); err != nil {
			return result, fmt.Errorf("coreupdate: target changed before replacement: %w", err)
		}
	}
	oldInfo, oldExists, err := snapshotTarget(targetPath)
	if err != nil {
		return result, err
	}
	if oldStateExists != oldExists {
		return result, ErrTargetChanged
	}
	backupPath := ""
	if oldExists {
		backupPath, err = copyBackup(root, targetPath)
		if err != nil {
			return result, fmt.Errorf("coreupdate: create rollback backup: %w", err)
		}
		if oldStateExists {
			if err := verifyFileHash(backupPath, oldState.SHA256, oldState.Size); err != nil {
				_ = removeIfExists(backupPath)
				return result, fmt.Errorf("coreupdate: rollback backup verification failed: %w", err)
			}
		}
	}
	if err := ensureTargetUnchanged(targetPath, oldInfo, oldExists); err != nil {
		_ = removeIfExists(backupPath)
		return result, err
	}
	if oldStateExists {
		if err := verifyFileHash(targetPath, oldState.SHA256, oldState.Size); err != nil {
			_ = removeIfExists(backupPath)
			return result, fmt.Errorf("coreupdate: target changed immediately before replacement: %w", err)
		}
	}
	if err := i.atomicReplace(downloaded.path, targetPath); err != nil {
		_ = removeIfExists(backupPath)
		return result, fmt.Errorf("coreupdate: atomic replace target: %w", err)
	}
	downloadConsumed = true
	result.Committed = true
	result.Version = manifest.Version
	result.Platform = manifest.Platform
	result.TargetPath = targetPath
	result.SHA256 = manifest.SHA256
	result.Size = manifest.Size

	fail := func(cause error) (Result, error) {
		result.RolledBack = false
		if rollbackErr := i.rollbackInstall(root, targetPath, statePath, backupPath, oldExists, oldStateExists, oldStateBytes); rollbackErr != nil {
			return result, errors.Join(cause, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		result.RolledBack = true
		return result, fmt.Errorf("%w; old version restored", cause)
	}
	if err := syncDir(root); err != nil {
		return fail(fmt.Errorf("coreupdate: sync target replacement: %w", err))
	}
	if err := secureFile(targetPath, 0o700); err != nil {
		return fail(fmt.Errorf("coreupdate: secure installed target: %w", err))
	}
	if _, err := VerifySignedManifest(manifestData, opts); err != nil {
		return fail(fmt.Errorf("coreupdate: post-install manifest verification failed: %w", err))
	}
	if err := verifyFileHash(targetPath, manifest.SHA256, manifest.Size); err != nil {
		return fail(fmt.Errorf("coreupdate: post-install artifact verification failed: %w", err))
	}
	newState := diskState{
		SchemaVersion: stateSchemaVersion,
		Version:       manifest.Version,
		Platform:      manifest.Platform,
		TargetName:    i.targetName,
		SHA256:        manifest.SHA256,
		Size:          manifest.Size,
		InstalledAt:   i.now().UTC().Format(time.RFC3339Nano),
	}
	if err := i.replaceState(root, statePath, newState); err != nil {
		return fail(fmt.Errorf("coreupdate: commit state: %w", err))
	}
	if backupPath != "" {
		if err := removeIfExists(backupPath); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("remove rollback backup: %v", err))
		}
	}
	_ = syncDir(root)
	return result, nil
}

func (i *Installer) verifyOptions(now time.Time) VerifyOptions {
	return VerifyOptions{
		PublicKey:        i.publicKey,
		AllowedVersions:  i.allowedVersions,
		AllowedPlatforms: i.allowedPlatforms,
		Platform:         i.platform,
		CurrentVersion:   i.currentVersion,
		Now:              now,
		ClockSkew:        i.clockSkew,
		MaxManifestBytes: i.maxManifestBytes,
	}
}

func snapshotTarget(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("coreupdate: inspect target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%w: target is a symbolic link", ErrSymlink)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("coreupdate: target is not a regular file")
	}
	return info, true, nil
}

func ensureTargetUnchanged(path string, oldInfo os.FileInfo, oldExists bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if oldExists {
			return ErrTargetChanged
		}
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: target became a symbolic link", ErrSymlink)
	}
	if !oldExists {
		return ErrTargetChanged
	}
	if !os.SameFile(oldInfo, info) || info.Size() != oldInfo.Size() {
		return ErrTargetChanged
	}
	return nil
}
