package coreupdate

import "errors"

// Sentinel errors are intentionally specific so callers can fail closed and
// report actionable configuration problems without parsing error strings.
var (
	ErrNoPublicKey          = errors.New("coreupdate: no trusted Ed25519 public key configured")
	ErrInvalidPublicKey     = errors.New("coreupdate: invalid Ed25519 public key")
	ErrInvalidManifest      = errors.New("coreupdate: invalid manifest")
	ErrManifestTooLarge     = errors.New("coreupdate: manifest exceeds size limit")
	ErrInvalidSignature     = errors.New("coreupdate: invalid manifest signature")
	ErrManifestExpired      = errors.New("coreupdate: manifest expired")
	ErrManifestNotYetValid  = errors.New("coreupdate: manifest is not yet valid")
	ErrVersionNotAllowed    = errors.New("coreupdate: manifest version is not allowed")
	ErrPlatformNotAllowed   = errors.New("coreupdate: manifest platform is not allowed")
	ErrVersionNotNewer      = errors.New("coreupdate: manifest version is not newer than current version")
	ErrClientTooOld         = errors.New("coreupdate: client version is below manifest minimum")
	ErrHTTPSRequired        = errors.New("coreupdate: manifest URL must use HTTPS")
	ErrCrossHostRedirect    = errors.New("coreupdate: cross-host redirect is not allowed")
	ErrDownloadTooLarge     = errors.New("coreupdate: download exceeds configured size limit")
	ErrDownloadSizeMismatch = errors.New("coreupdate: downloaded size does not match manifest")
	ErrHashMismatch         = errors.New("coreupdate: SHA-256 mismatch")
	ErrInvalidTarget        = errors.New("coreupdate: invalid target name")
	ErrUnmanagedTarget      = errors.New("coreupdate: refusing to overwrite a target not managed by coreupdate")
	ErrTargetChanged        = errors.New("coreupdate: target changed during update")
	ErrSymlink              = errors.New("coreupdate: symbolic links are not allowed")
	ErrStateCorrupt         = errors.New("coreupdate: managed state is corrupt")
)
