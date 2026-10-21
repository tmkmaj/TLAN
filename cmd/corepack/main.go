package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/internal/coreupdate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "corepack signs and verifies Ed25519-signed core update manifests.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  corepack sign -manifest <unsigned.json> -key <private-key-file> -out <signed.json>")
	fmt.Fprintln(w, "  corepack verify -manifest <signed.json> -public-key <public-key-file> [options]")
	fmt.Fprintln(w, "  corepack help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Verify options: -client-version, -platform, -allowed-versions, -allowed-platforms, -now")
	fmt.Fprintln(w, "The private key is read only from the file supplied to sign and is never printed.")
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("corepack sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "unsigned manifest JSON file")
	keyPath := fs.String("key", "", "Ed25519 private key file")
	outPath := fs.String("out", "", "signed manifest output file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *manifestPath == "" || *keyPath == "" || *outPath == "" {
		fmt.Fprintln(stderr, "sign requires -manifest, -key, and -out")
		return 2
	}
	if sameFilePath(*keyPath, *outPath) {
		fmt.Fprintln(stderr, "refusing to write the signed manifest over the private key")
		return 2
	}
	data, err := readFileLimited(*manifestPath, coreupdate.DefaultMaxManifestBytes)
	if err != nil {
		fmt.Fprintf(stderr, "read manifest: %v\n", err)
		return 1
	}
	manifest, err := coreupdate.ParseManifest(data, coreupdate.DefaultMaxManifestBytes)
	if err != nil {
		fmt.Fprintf(stderr, "parse manifest: %v\n", err)
		return 1
	}
	if manifest.Signature != "" {
		fmt.Fprintln(stderr, "refusing to re-sign a manifest that already has a signature")
		return 1
	}
	privateKey, err := coreupdate.ReadPrivateKeyFile(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read private key: %v\n", err)
		return 1
	}
	signed, err := coreupdate.SignManifest(manifest, privateKey)
	if err != nil {
		fmt.Fprintf(stderr, "sign manifest: %v\n", err)
		return 1
	}
	output, err := coreupdate.MarshalSignedManifest(signed)
	if err != nil {
		fmt.Fprintf(stderr, "marshal signed manifest: %v\n", err)
		return 1
	}
	if err := writeFileSync(*outPath, output, 0o600); err != nil {
		fmt.Fprintf(stderr, "write signed manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "signed version=%s platform=%s\n", signed.Version, signed.Platform)
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("corepack verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "signed manifest JSON file")
	publicKeyPath := fs.String("public-key", "", "trusted Ed25519 public key file")
	clientVersion := fs.String("client-version", "0.0.0", "current client version")
	platform := fs.String("platform", runtime.GOOS+"-"+runtime.GOARCH, "expected platform")
	allowedVersions := fs.String("allowed-versions", "", "comma-separated allowed manifest versions")
	allowedPlatforms := fs.String("allowed-platforms", "", "comma-separated allowed manifest platforms")
	nowText := fs.String("now", "", "RFC3339 verification time (default: now)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *manifestPath == "" || *publicKeyPath == "" {
		fmt.Fprintln(stderr, "verify requires -manifest and -public-key")
		return 2
	}
	data, err := readFileLimited(*manifestPath, coreupdate.DefaultMaxManifestBytes)
	if err != nil {
		fmt.Fprintf(stderr, "read manifest: %v\n", err)
		return 1
	}
	publicKey, err := coreupdate.ReadPublicKeyFile(*publicKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read public key: %v\n", err)
		return 1
	}
	opts := coreupdate.VerifyOptions{
		PublicKey:        publicKey,
		CurrentVersion:   *clientVersion,
		Platform:         *platform,
		ClockSkew:        5 * time.Minute,
		MaxManifestBytes: coreupdate.DefaultMaxManifestBytes,
	}
	if *allowedVersions != "" {
		opts.AllowedVersions = splitList(*allowedVersions)
	}
	if *allowedPlatforms != "" {
		opts.AllowedPlatforms = splitList(*allowedPlatforms)
	}
	if *nowText != "" {
		now, err := time.Parse(time.RFC3339Nano, *nowText)
		if err != nil {
			fmt.Fprintf(stderr, "parse -now: %v\n", err)
			return 2
		}
		opts.Now = now
	}
	manifest, err := coreupdate.VerifySignedManifest(data, opts)
	if err != nil {
		fmt.Fprintf(stderr, "verify manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "OK version=%s platform=%s\n", manifest.Version, manifest.Platform)
	return 0
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func sameFilePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		if runtime.GOOS == "windows" {
			if strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb)) {
				return true
			}
		} else if filepath.Clean(aa) == filepath.Clean(bb) {
			return true
		}
	}
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}
