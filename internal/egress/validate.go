package egress

import (
	"net"
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	identifierPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	windowsDriveAbsolute = regexp.MustCompile(`^[A-Za-z]:\\`)
	reservedWindowsNames = regexp.MustCompile(`^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
)

// ValidateProfilesDocument validates the complete profile document and all
// profile-level uniqueness constraints.
func ValidateProfilesDocument(doc ProfilesDocument) error {
	if doc.SchemaVersion != SchemaVersion {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "schemaVersion must be %d", SchemaVersion)
	}
	if len(doc.Profiles) > MaxProfiles {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "at most %d profiles are supported", MaxProfiles)
	}
	ids := make(map[string]struct{}, len(doc.Profiles))
	names := make(map[string]struct{}, len(doc.Profiles))
	for _, profile := range doc.Profiles {
		if !validIdentifier(profile.ID) {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "profile id %q is invalid", profile.ID)
		}
		if _, exists := ids[profile.ID]; exists {
			return codedError(CodeDuplicateProfile, ErrDuplicateProfile, "duplicate profile id %q", profile.ID)
		}
		ids[profile.ID] = struct{}{}
		nameKey := strings.ToLower(profile.Name)
		if _, exists := names[nameKey]; exists {
			return codedError(CodeDuplicateProfile, ErrDuplicateProfile, "duplicate profile name %q", profile.Name)
		}
		names[nameKey] = struct{}{}
		if err := ValidateProfile(profile); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProfile validates one profile, including duplicate rule ids, names,
// and case-insensitive executable paths.
func ValidateProfile(profile EgressProfile) error {
	if !validIdentifier(profile.ID) {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "profile id %q is invalid", profile.ID)
	}
	if err := validateName("profile name", profile.Name); err != nil {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%v", err)
	}
	if profile.Version == 0 {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "profile version must be positive")
	}
	if err := validateServer(profile.Server); err != nil {
		return err
	}
	if err := validatePolicy(profile.Policy); err != nil {
		return err
	}
	if !profile.DesiredState.Valid() {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "desiredState must be stopped or running")
	}
	if len(profile.Rules) == 0 {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "at least one application rule is required")
	}
	if len(profile.Rules) > MaxRules {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "at most %d application rules are supported", MaxRules)
	}

	enabled := 0
	ids := make(map[string]struct{}, len(profile.Rules))
	names := make(map[string]struct{}, len(profile.Rules))
	paths := make(map[string]struct{}, len(profile.Rules))
	for _, rule := range profile.Rules {
		if err := ValidateRule(rule); err != nil {
			return err
		}
		if _, exists := ids[rule.ID]; exists {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "duplicate rule id %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		nameKey := strings.ToLower(rule.Name)
		if _, exists := names[nameKey]; exists {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "duplicate rule name %q", rule.Name)
		}
		names[nameKey] = struct{}{}
		normalized, err := NormalizeExePath(rule.ExePath)
		if err != nil {
			return err
		}
		pathKey := ExePathKey(normalized)
		if _, exists := paths[pathKey]; exists {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "duplicate rule executable path %q", rule.ExePath)
		}
		paths[pathKey] = struct{}{}
		if rule.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "at least one enabled application rule is required to run")
	}
	return nil
}

// ValidateRule validates one executable-path rule. The path is compared using
// its normalized, case-insensitive Windows key.
func ValidateRule(rule AppRule) error {
	if !validIdentifier(rule.ID) {
		return codedError(CodeInvalidRule, ErrInvalidRule, "rule id %q is invalid", rule.ID)
	}
	if err := validateName("rule name", rule.Name); err != nil {
		return codedError(CodeInvalidRule, ErrInvalidRule, "%v", err)
	}
	if _, err := NormalizeExePath(rule.ExePath); err != nil {
		return err
	}
	if len(rule.Protocols) == 0 {
		return codedError(CodeInvalidRule, ErrInvalidRule, "rule %q must select at least one protocol", rule.Name)
	}
	seen := make(map[Protocol]struct{}, len(rule.Protocols))
	for _, protocol := range rule.Protocols {
		switch protocol {
		case ProtocolTCP, ProtocolUDP:
		default:
			return codedError(CodeUnsupported, ErrUnsupported, "rule %q protocol %q is not supported; only tcp and udp are supported", rule.Name, protocol)
		}
		if _, exists := seen[protocol]; exists {
			return codedError(CodeInvalidRule, ErrInvalidRule, "rule %q contains duplicate protocol %q", rule.Name, protocol)
		}
		seen[protocol] = struct{}{}
	}
	return nil
}

// NormalizeExePath returns a canonical absolute Windows drive path. UNC,
// device, drive-relative, traversal, reserved-name, and control-character paths
// are rejected rather than normalized into something ambiguous.
func NormalizeExePath(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path must be a non-empty absolute Windows path")
	}
	for _, r := range raw {
		if unicode.IsControl(r) || r == '\uFFFD' {
			return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path contains an invalid character")
		}
	}
	replaced := strings.ReplaceAll(raw, "/", `\`)
	if strings.HasPrefix(replaced, `\\`) {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "UNC and device executable paths are not supported")
	}
	if !windowsDriveAbsolute.MatchString(replaced) {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path must be an absolute Windows drive path")
	}
	if hasParentComponent(replaced) {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path must not contain parent traversal")
	}

	// filepath.Clean is the platform contract; the portable path.Clean call
	// keeps canonicalization identical on non-Windows test hosts as well.
	_ = filepath.Clean(replaced)
	clean := strings.ReplaceAll(path.Clean(strings.ReplaceAll(replaced, `\`, "/")), "/", `\`)
	if !windowsDriveAbsolute.MatchString(clean) || hasParentComponent(clean) {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path is not a canonical absolute path")
	}
	if len(clean) <= 3 {
		return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path must name a file")
	}
	segments := strings.Split(clean[3:], `\`)
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path contains an invalid segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path contains a non-portable trailing dot or space")
		}
		if strings.ContainsAny(segment, `<>:"|?*`) {
			return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path contains a non-portable Windows character")
		}
		stem := segment
		if index := strings.IndexByte(stem, '.'); index >= 0 {
			stem = stem[:index]
		}
		if reservedWindowsNames.MatchString(strings.ToUpper(stem)) {
			return "", codedError(CodeInvalidRule, ErrInvalidRule, "executable path uses reserved Windows name %q", stem)
		}
	}
	return clean, nil
}

// ExePathKey is the case-insensitive comparison key for a normalized path.
func ExePathKey(normalized string) string { return strings.ToLower(normalized) }

// NormalizeRule canonicalizes paths and protocol names without accepting
// unsupported protocols.
func NormalizeRule(rule AppRule) (AppRule, error) {
	normalizedPath, err := NormalizeExePath(rule.ExePath)
	if err != nil {
		return AppRule{}, err
	}
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.ExePath = normalizedPath
	rule.Protocols = append([]Protocol(nil), rule.Protocols...)
	for i := range rule.Protocols {
		rule.Protocols[i] = Protocol(strings.ToLower(strings.TrimSpace(string(rule.Protocols[i]))))
	}
	if err := ValidateRule(rule); err != nil {
		return AppRule{}, err
	}
	return rule, nil
}

// NormalizeProfile returns a validated deep copy with normalized paths.
func NormalizeProfile(profile EgressProfile) (EgressProfile, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Server.Endpoint = strings.TrimSpace(profile.Server.Endpoint)
	profile.Server.ServerName = strings.TrimSpace(profile.Server.ServerName)
	profile.Server.TrustedCARef = strings.TrimSpace(profile.Server.TrustedCARef)
	profile.Server.CredentialRef = strings.TrimSpace(profile.Server.CredentialRef)
	profile.Policy.IPv6Policy = strings.ToLower(strings.TrimSpace(profile.Policy.IPv6Policy))
	profile.Policy.DNSPolicy = strings.ToLower(strings.TrimSpace(profile.Policy.DNSPolicy))
	profile.Policy.TargetAllowList = append([]string(nil), profile.Policy.TargetAllowList...)
	rules := profile.Rules
	profile.Rules = make([]AppRule, len(rules))
	for i, rule := range rules {
		normalized, err := NormalizeRule(rule)
		if err != nil {
			return EgressProfile{}, err
		}
		profile.Rules[i] = normalized
	}
	if err := ValidateProfile(profile); err != nil {
		return EgressProfile{}, err
	}
	return profile, nil
}

func ValidateProfilesDocumentNormalized(doc ProfilesDocument) (ProfilesDocument, error) {
	doc.Profiles = append([]EgressProfile(nil), doc.Profiles...)
	for i, profile := range doc.Profiles {
		normalized, err := NormalizeProfile(profile)
		if err != nil {
			return ProfilesDocument{}, err
		}
		doc.Profiles[i] = normalized
	}
	if err := ValidateProfilesDocument(doc); err != nil {
		return ProfilesDocument{}, err
	}
	return doc, nil
}

func validateServer(server EgressServer) error {
	if err := validateHost("server endpoint", server.Endpoint); err != nil {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%v", err)
	}
	if server.Port < 1 || server.Port > 65535 {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "server port must be between 1 and 65535")
	}
	if server.ServerName != "" {
		if err := validateHost("server name", server.ServerName); err != nil {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "%v", err)
		}
	}
	if server.TrustedCARef != "" && !validIdentifier(server.TrustedCARef) {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "trusted CA reference is invalid")
	}
	if !validIdentifier(server.CredentialRef) {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "credential reference is invalid")
	}
	return nil
}

func validatePolicy(policy EgressPolicy) error {
	switch policy.IPv6Policy {
	case IPv6PolicyBlock, IPv6PolicyProxy:
	default:
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "ipv6Policy must be block or proxy")
	}
	switch policy.DNSPolicy {
	case DNSPolicyRemote, DNSPolicyLocal, DNSPolicyBlock:
	default:
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "dnsPolicy must be remote, local, or block")
	}
	if len(policy.TargetAllowList) > MaxTargetAllowList {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "at most %d target allow-list entries are supported", MaxTargetAllowList)
	}
	seen := make(map[string]struct{}, len(policy.TargetAllowList))
	for _, target := range policy.TargetAllowList {
		if err := validateTargetSpec(target); err != nil {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "target allow-list entry %q is invalid: %v", target, err)
		}
		if _, exists := seen[target]; exists {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "duplicate target allow-list entry %q", target)
		}
		seen[target] = struct{}{}
	}
	return nil
}

func validateTargetSpec(target string) error {
	if target == "" || strings.TrimSpace(target) != target {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "entry must not be empty or padded")
	}
	if _, err := netip.ParsePrefix(target); err == nil {
		return nil
	}
	if addr, err := netip.ParseAddr(target); err == nil && addr.Zone() == "" {
		return nil
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if err := validateHost("target host", host); err != nil {
			return err
		}
		if port == "" {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "target port is empty")
		}
		var portNumber int
		for _, r := range port {
			if r < '0' || r > '9' {
				return codedError(CodeInvalidProfile, ErrInvalidProfile, "target port must be numeric")
			}
			portNumber = portNumber*10 + int(r-'0')
		}
		if portNumber < 1 || portNumber > 65535 {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "target port must be between 1 and 65535")
		}
		return nil
	}
	return validateHost("target host", target)
}

func validateHost(label, value string) error {
	if value == "" {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is required", label)
	}
	if strings.TrimSpace(value) != value || len(value) > 253 {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is invalid", label)
	}
	if strings.ContainsAny(value, "/\\@?#[] \t\r\n") {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is invalid", label)
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Zone() != "" {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s must not contain an IPv6 zone", label)
		}
		return nil
	}
	if strings.Contains(value, ":") {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s must not include a port", label)
	}
	host := strings.TrimSuffix(value, ".")
	if host == "" {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is invalid", label)
	}
	for _, labelPart := range strings.Split(host, ".") {
		if labelPart == "" || len(labelPart) > 63 || labelPart[0] == '-' || labelPart[len(labelPart)-1] == '-' {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is invalid", label)
		}
		for _, r := range labelPart {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is invalid", label)
			}
		}
	}
	return nil
}

func validateName(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s is required", label)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxNameLength {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s must be at most %d UTF-8 characters", label, MaxNameLength)
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\uFFFD' {
			return codedError(CodeInvalidProfile, ErrInvalidProfile, "%s contains an invalid character", label)
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if !identifierPattern.MatchString(value) {
		return false
	}
	return !ReservedIdentifier(value)
}

// ReservedIdentifier reports whether value is an empty or Windows device name
// that should not be used as a profile, rule, or secret identifier.
func ReservedIdentifier(value string) bool {
	return value == "" || reservedWindowsNames.MatchString(strings.ToUpper(value))
}

func hasParentComponent(value string) bool {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}
