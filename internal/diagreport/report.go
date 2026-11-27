package diagreport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	// SchemaVersion is the only FRP diagnostic report schema accepted by the
	// control plane. Keep it aligned with the desktop export schema.
	SchemaVersion = 1

	// MaxReportBytes bounds the complete FRP JSON object stored per report.
	MaxReportBytes = 2 << 20

	// MaxRequestBytes leaves room for the legacy checks envelope while keeping
	// the total diagnostic request bounded.
	MaxRequestBytes = MaxReportBytes + (512 << 10)

	MaxProfiles = 32
)

var (
	diagnosticPrivateKey  = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	diagnosticURLUserInfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]+:[^/\s@]+@)`)
	diagnosticSecretText  = regexp.MustCompile(`(?i)((?:token|password|passwd|secret[ _-]?key|secret|capability|credential|psk|api_?key|tls_?key|pre_?shared_?key|private_?key)\s*["\']?\s*[=:]\s*["\']?)([^\s&,;\"\'\\]+)`)
	diagnosticAuth        = regexp.MustCompile(`(?i)(authorization\s*:\s*(?:(?:bearer|basic)\s+)?["\']?)[^\s,;\"\'\\]+`)
)

type validationState struct {
	nodes int
}

// Sanitize validates a complete FRP diagnostic report and returns a compact,
// redacted JSON object. Validation is intentionally stricter than the legacy
// checks path: the report must be a schema-v1 object with only the documented
// top-level fields, bounded structure, and no duplicate object keys.
func Sanitize(raw json.RawMessage) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, errors.New("frp diagnostic report is empty")
	}
	if len(raw) > MaxReportBytes {
		return nil, fmt.Errorf("frp diagnostic report exceeds %d bytes", MaxReportBytes)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid frp diagnostic report: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("frp diagnostic report must be a JSON object")
	}
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	state := validationState{}
	sanitized, err := sanitizeValue(root, "", 0, &state)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("encode frp diagnostic report: %w", err)
	}
	if len(encoded) > MaxReportBytes {
		return nil, fmt.Errorf("frp diagnostic report exceeds %d bytes after normalization", MaxReportBytes)
	}
	return json.RawMessage(encoded), nil
}

func validateRoot(root map[string]any) error {
	allowed := map[string]struct{}{
		"schema_version": {},
		"generated_at":   {},
		"profiles":       {},
	}
	for key := range root {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown frp diagnostic report field %q", key)
		}
	}
	version, ok := root["schema_version"].(json.Number)
	if !ok || version.String() != fmt.Sprint(SchemaVersion) {
		return fmt.Errorf("frp diagnostic schema_version must be %d", SchemaVersion)
	}
	generated, ok := root["generated_at"].(string)
	if !ok {
		return errors.New("frp diagnostic generated_at must be a timestamp")
	}
	parsed, err := time.Parse(time.RFC3339Nano, generated)
	if err != nil || parsed.IsZero() {
		return errors.New("frp diagnostic generated_at must be a valid RFC3339 timestamp")
	}
	profiles, ok := root["profiles"].([]any)
	if !ok {
		return errors.New("frp diagnostic profiles must be an array")
	}
	if len(profiles) > MaxProfiles {
		return fmt.Errorf("frp diagnostic profiles exceeds %d entries", MaxProfiles)
	}
	seen := make(map[string]struct{}, len(profiles))
	for index, item := range profiles {
		profile, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("frp diagnostic profile %d must be an object", index)
		}
		id, ok := profile["profile_id"].(string)
		if !ok || strings.TrimSpace(id) == "" || len(id) > 128 {
			return fmt.Errorf("frp diagnostic profile %d has an invalid profile_id", index)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("frp diagnostic profile_id %q is duplicated", id)
		}
		seen[id] = struct{}{}
		if _, ok := profile["snapshot"].(map[string]any); !ok {
			return fmt.Errorf("frp diagnostic profile %q snapshot must be an object", id)
		}
		if _, ok := profile["logs"].([]any); !ok {
			return fmt.Errorf("frp diagnostic profile %q logs must be an array", id)
		}
	}
	return nil
}

func sanitizeValue(value any, key string, depth int, state *validationState) (any, error) {
	if depth > 24 {
		return nil, errors.New("frp diagnostic report nesting is too deep")
	}
	state.nodes++
	if state.nodes > 100000 {
		return nil, errors.New("frp diagnostic report has too many values")
	}
	switch item := value.(type) {
	case string:
		if len(item) > 128<<10 {
			return nil, errors.New("frp diagnostic string is too long")
		}
		if sensitiveKey(key) {
			return "[已隐藏]", nil
		}
		return redactText(item), nil
	case json.Number:
		if sensitiveKey(key) {
			return "[已隐藏]", nil
		}
		return item, nil
	case bool:
		return item, nil
	case nil:
		return nil, nil
	case []any:
		if limit := arrayLimit(key); limit > 0 && len(item) > limit {
			return nil, fmt.Errorf("frp diagnostic %s array exceeds %d entries", key, limit)
		}
		out := make([]any, len(item))
		for i := range item {
			child, err := sanitizeValue(item[i], key, depth+1, state)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case map[string]any:
		if len(item) > 128 {
			return nil, fmt.Errorf("frp diagnostic object %q has too many fields", key)
		}
		out := make(map[string]any, len(item))
		for childKey, childValue := range item {
			if len(childKey) == 0 || len(childKey) > 128 {
				return nil, errors.New("frp diagnostic object key is invalid")
			}
			child, err := sanitizeValue(childValue, childKey, depth+1, state)
			if err != nil {
				return nil, err
			}
			out[childKey] = child
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported frp diagnostic value type %T", value)
	}
}

func sensitiveKey(key string) bool {
	compact := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	if compact == "" {
		return false
	}
	for _, suffix := range []string{
		"token", "password", "passwd", "secret", "secretkey", "capability", "credential", "authorization",
		"psk", "apikey", "tlskey", "presharedkey", "privatekey",
	} {
		if compact == suffix || strings.HasSuffix(compact, suffix) {
			return true
		}
	}
	return false
}

func redactText(value string) string {
	value = diagnosticPrivateKey.ReplaceAllString(value, "[已隐藏私钥]")
	value = diagnosticURLUserInfo.ReplaceAllString(value, "${1}[已隐藏]@")
	value = diagnosticAuth.ReplaceAllString(value, "${1}[已隐藏]")
	return diagnosticSecretText.ReplaceAllString(value, "${1}[已隐藏]")
}

func arrayLimit(key string) int {
	switch key {
	case "profiles":
		return MaxProfiles
	case "logs":
		return 500
	case "rules":
		return 256
	case "visitors":
		return 128
	case "endpoints":
		return 512
	case "managed_leases", "collection_errors":
		return 64
	case "egress":
		return 128
	case "routes", "target_gateways":
		return 256
	case "ca_certificates", "server_certificates":
		return 16
	default:
		return 2048
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("frp diagnostic report contains trailing JSON")
	}
	return fmt.Errorf("invalid trailing frp diagnostic JSON: %w", err)
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 24 {
		return errors.New("frp diagnostic report nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid frp diagnostic report: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid frp diagnostic object: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("frp diagnostic object key must be a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate frp diagnostic field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("invalid frp diagnostic object: %w", err)
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("invalid frp diagnostic array: %w", err)
		}
	default:
		return errors.New("unexpected frp diagnostic JSON delimiter")
	}
	return nil
}
