package frp

import (
	"regexp"
	"strings"
	"sync"
)

const logRingCapacity = 500

type logRing struct {
	mu      sync.Mutex
	lines   []string
	secrets []string
}

var logCredential = regexp.MustCompile(`(?i)((?:token|password|secret|authorization)\s*[=:]\s*)([^\s&,;]+)`)

func (r *logRing) setSecrets(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets = r.secrets[:0]
	for _, secret := range secrets {
		if secret != "" {
			r.secrets = append(r.secrets, secret)
		}
	}
}

func (r *logRing) add(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, secret := range r.secrets {
		line = strings.ReplaceAll(line, secret, "[已隐藏]")
	}
	line = logCredential.ReplaceAllString(line, "${1}[已隐藏]")
	if len(r.lines) == logRingCapacity {
		copy(r.lines, r.lines[1:])
		r.lines[len(r.lines)-1] = line
	} else {
		r.lines = append(r.lines, line)
	}
}

func (r *logRing) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *logRing) text() string {
	return strings.Join(r.snapshot(), "\n")
}

func (r *logRing) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = nil
}
