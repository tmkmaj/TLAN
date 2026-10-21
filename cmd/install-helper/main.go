// install-helper contains the operations that cannot safely be done with shell
// text substitutions: configuration migration and verified HTTPS readiness.
package main

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/internal/config"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("expected prepare, probe, ports or verify-elf")
	}
	switch args[0] {
	case "prepare":
		if len(args) != 3 {
			return errors.New("prepare SOURCE_CONFIG DESTINATION_CONFIG")
		}
		return prepare(args[1], args[2])
	case "probe":
		if len(args) != 3 {
			return errors.New("probe http|https SECONDS")
		}
		seconds, err := strconv.Atoi(args[2])
		if err != nil || seconds < 1 || seconds > 120 {
			return errors.New("invalid timeout")
		}
		return probe(args[1], time.Duration(seconds)*time.Second)
	case "ports":
		if len(args) != 2 {
			return errors.New("ports CONFIG")
		}
		cfg, err := config.LoadFile(args[1])
		if err != nil {
			return err
		}
		return checkPorts(cfg)
	case "verify-elf":
		if len(args) < 2 {
			return errors.New("verify-elf FILE...")
		}
		for _, path := range args[1:] {
			if err := verifyELF(path); err != nil {
				return err
			}
		}
		return nil
	case "set-bind-capability":
		if len(args) != 2 {
			return errors.New("set-bind-capability CADDY_BINARY")
		}
		return setBindCapability(args[1])
	}
	return errors.New("unknown operation")
}

func prepare(source, destination string) error {
	var cfg config.Config
	var err error
	if _, err = os.Stat(source); errors.Is(err, os.ErrNotExist) {
		cfg, _, err = config.LoadOrCreate(destination)
		if err != nil {
			return err
		}
		if _, statErr := os.Stat(filepath.Join(filepath.Dir(source), "state.json")); statErr == nil {
			cfg.Storage.DataDir = "."
		}
	} else {
		if err != nil {
			return err
		}
		cfg, err = config.LoadFile(source)
		if err != nil {
			return err
		}
	}
	// Preserve credentials, network, storage, STUN and the optional TCP relay.
	// Only move the control listener behind the bundled HTTPS proxy.
	cfg.Server.Listen = "127.0.0.1:8080"
	cfg.Server.TLSCert, cfg.Server.TLSKey = "", ""
	if err := cfg.Validate(); err != nil {
		return err
	}
	dataDir := cfg.Storage.DataDir
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(filepath.Dir(source), dataDir)
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if strings.ContainsAny(dataDir, "\r\n") {
		return errors.New("storage directory contains a newline")
	}
	// A dedicated service must not take ownership of an arbitrary shared path.
	base, err := filepath.Abs(filepath.Dir(source))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, dataDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("custom storage outside /var/lib/lanmesh requires manual deployment; existing files were not changed")
	}
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination, contents, 0600); err != nil {
		return err
	}
	fmt.Println(dataDir)
	return nil
}

func checkPorts(cfg config.Config) error {
	var closers []interface{ Close() error }
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	for _, addr := range []string{":80", ":8443", "127.0.0.1:2019", cfg.Server.Listen, cfg.Server.RelayListen} {
		if addr == "" {
			continue
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP %s unavailable: %w", addr, err)
		}
		closers = append(closers, l)
	}
	if addr := cfg.Server.STUNListen; addr != "" && !strings.EqualFold(strings.TrimSpace(addr), "off") {
		l, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("UDP %s unavailable: %w", addr, err)
		}
		closers = append(closers, l)
	}
	return nil
}

func probe(scheme string, timeout time.Duration) error {
	url := "http://127.0.0.1:8080/health"
	port := "8080"
	if scheme == "https" {
		url, port = "https://8.163.21.82:8443/health", "8443"
	} else if scheme != "http" {
		return errors.New("expected http or https")
	}
	transport := &http.Transport{
		// Test the local gateway with the public IP certificate identity. No SNI
		// override, proxy environment, or disabled certificate verification.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var last error
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			var body struct {
				Status string `json:"status"`
			}
			err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4096)).Decode(&body)
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode == 200 && body.Status == "ok" {
				return nil
			}
			err = fmt.Errorf("unexpected health response: HTTP %d", resp.StatusCode)
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s readiness failed: %w", scheme, last)
		case <-time.After(time.Second):
		}
	}
}

func verifyELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
		return fmt.Errorf("%s is not Linux amd64", path)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("%s needs a dynamic loader; CentOS 7 glibc compatibility is not assured", path)
		}
	}
	return nil
}
