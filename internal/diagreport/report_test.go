package diagreport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeRedactsSecretsAndPreservesStructure(t *testing.T) {
	raw := json.RawMessage(`{
  "schema_version": 1,
  "generated_at": "2026-10-22T10:00:00Z",
  "profiles": [{
    "profile_id": "profile-a",
    "profile_name": "office",
    "snapshot": {"Running": true, "Rules": [{"Name": "tcp", "ErrorDetail": "token=token-secret"}]},
    "logs": [
      "capability=capability-secret",
      "Authorization: Bearer bearer-secret",
      "password=password-secret",
      "\"token\":\"quoted-secret\"",
      "psk=psk-secret apiKey=apikey-secret tls_key=tls-secret",
      "secretKey = text-secret-key-secret",
      "http://proxyuser:proxy-secret@127.0.0.1:8080/connect",
      "-----BEGIN PRIVATE KEY-----\nprivate-key-secret\n-----END PRIVATE KEY-----"
    ],
    "managed_leases": [{"lease_id_masked": "leas…1234", "capability": "lease-secret", "apiKey": "camel-api-secret", "pre_shared_key": "snake-psk-secret", "secretKey": "camel-secret-key-secret", "secret_key": "snake-secret-key-secret"}]
  }]
}`)
	sanitized, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"token-secret", "capability-secret", "bearer-secret", "password-secret", "quoted-secret", "psk-secret", "apikey-secret", "tls-secret", "proxy-secret", "camel-api-secret", "snake-psk-secret", "private-key-secret", "lease-secret", "text-secret-key-secret", "camel-secret-key-secret", "snake-secret-key-secret"} {
		if bytes.Contains(sanitized, []byte(secret)) {
			t.Fatalf("sanitized report still contains %q: %s", secret, sanitized)
		}
	}
	if !bytes.Contains(sanitized, []byte(`"profiles"`)) || !bytes.Contains(sanitized, []byte(`"Running":true`)) {
		t.Fatalf("sanitized report lost structure: %s", sanitized)
	}
}

func TestSanitizeRejectsStrictSchemaViolations(t *testing.T) {
	tests := map[string]string{
		"unknown root field": `{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[],"token":"secret"}`,
		"wrong schema":       `{"schema_version":2,"generated_at":"2026-10-22T10:00:00Z","profiles":[]}`,
		"bad timestamp":      `{"schema_version":1,"generated_at":"yesterday","profiles":[]}`,
		"duplicate key":      `{"schema_version":1,"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[]}`,
		"missing logs":       `{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[{"profile_id":"p","snapshot":{}}]}`,
		"trailing JSON":      `{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[]} {}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Sanitize(json.RawMessage(raw)); err == nil {
				t.Fatal("invalid report was accepted")
			}
		})
	}
}

func TestSanitizeRejectsOversizedReport(t *testing.T) {
	raw := json.RawMessage(`{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[{"profile_id":"p","snapshot":{},"logs":["` + strings.Repeat("x", MaxReportBytes) + `"]}]}`)
	if _, err := Sanitize(raw); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized report error = %v", err)
	}
}
