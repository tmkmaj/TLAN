package frp

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/private-radminlan/lanmesh/core"
)

var (
	// ErrDependencyIsolation marks configurations that mix a Mesh-dependent
	// process group with an independent visitor process group.
	ErrDependencyIsolation = errors.New("Mesh-dependent rules and independent visitors require separate profiles")
	// ErrReservedTarget marks targets that would expose TLAN/FRP control or
	// cloud metadata endpoints through an ordinary proxy rule.
	ErrReservedTarget = errors.New("target is reserved by TLAN or FRP")

	tlanMeshPools = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
	fixedTargetReservations = []TargetReservation{
		{Host: "127.0.0.1", Port: 7000, Purpose: "FRPS control listener"},
		{Host: "127.0.0.1", Port: 7400, Purpose: "FRPC default administration listener"},
		{Host: "127.0.0.1", Port: 7500, Purpose: "FRPS dashboard"},
		{Host: "127.0.0.1", Port: 9093, Purpose: "TLAN FRP authorization plugin"},
		{Host: "127.0.0.1", Port: 17401, Purpose: "managed FRPC administration listener"},
	}
	reservedTargetAddresses = map[netip.Addr]string{
		netip.MustParseAddr("169.254.169.254"): "cloud instance metadata",
		netip.MustParseAddr("169.254.170.2"):   "container task metadata",
		netip.MustParseAddr("169.254.0.23"):    "cloud instance metadata",
		netip.MustParseAddr("100.100.100.200"): "cloud instance metadata",
		netip.MustParseAddr("168.63.129.16"):   "cloud platform management",
	}
)

// TargetReservation is a host/port that runtime components must never expose
// as an ordinary business target or visitor listener. Callers pass ports that
// are allocated dynamically, such as a local frpc administration port or the
// TargetGateway listener for another rule.
type TargetReservation struct {
	Host    string
	Port    int
	Purpose string
	// AllowVisitorBind permits an identified visitor listener to use its own
	// reservation. A different profile or visitor still conflicts, and any
	// business rule targeting the endpoint is always rejected.
	AllowVisitorBind bool
	OwnerProfileID   string
	VisitorID        string
}

func ValidateConfig(cfg Config) error {
	return ValidateConfigWithReservations(cfg, nil)
}

// ValidateConfigWithReservations applies the same base policy as
// ValidateConfig and additionally rejects caller-supplied dynamic management
// or internal gateway endpoints.
func ValidateConfigWithReservations(cfg Config, reservations []TargetReservation) error {
	if cfg.SchemaVersion != SchemaVersion && cfg.SchemaVersion != LegacySchema {
		return unsupported("schemaVersion must be %d", SchemaVersion)
	}
	if !identifierValid(cfg.Profile.ID) {
		return unsupported("profile id is invalid")
	}
	if err := validateName("profile name", cfg.Profile.Name); err != nil {
		return err
	}
	if cfg.Profile.CoreVersion != CoreVersion {
		return unsupported("coreVersion must be %s", CoreVersion)
	}
	if err := ValidateServer(cfg.Profile.Server); err != nil {
		return err
	}
	if len(cfg.Profile.Rules) > MaxRules {
		return unsupported("at most %d rules are supported", MaxRules)
	}
	if len(cfg.Profile.Visitors) > MaxVisitors {
		return unsupported("at most %d visitors are supported", MaxVisitors)
	}

	ids := make(map[string]struct{}, len(cfg.Profile.Rules))
	names := make(map[string]struct{}, len(cfg.Profile.Rules))
	hasMeshTarget := false
	hasIndependentTarget := false
	hasSubdomain := false
	ports := make(map[string]string, len(cfg.Profile.Rules))
	domains := make(map[string]string, len(cfg.Profile.Rules))
	for _, rule := range cfg.Profile.Rules {
		if !identifierValid(rule.ID) {
			return unsupported("rule id %q is invalid", rule.ID)
		}
		if _, exists := ids[rule.ID]; exists {
			return unsupported("duplicate rule id %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}

		nameKey := strings.ToLower(rule.Name)
		if err := validateName("rule name", rule.Name); err != nil {
			return err
		}
		if _, exists := names[nameKey]; exists {
			return unsupported("duplicate rule name %q", rule.Name)
		}
		names[nameKey] = struct{}{}

		switch rule.Type {
		case "tcp", "udp", "http", "https", "stcp", "sudp", "tcpmux", "xtcp":
		default:
			return unsupported("rule %q type must be tcp, udp, http, https, stcp, sudp, tcpmux or xtcp", rule.Name)
		}
		if err := validateAllowUsers(rule); err != nil {
			return err
		}
		switch rule.Transport.ProxyProtocolVersion {
		case "", "v1", "v2":
		default:
			return unsupported("rule %q proxyProtocolVersion must be v1, v2 or empty", rule.Name)
		}
		if err := validateTarget(rule); err != nil {
			return err
		}
		if rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self" {
			hasMeshTarget = true
		} else {
			hasIndependentTarget = true
		}
		if err := validatePort("local target port", rule.Target.Port); err != nil {
			return err
		}
		switch rule.Type {
		case "tcp", "udp":
			if rule.SecretRef != "" {
				return unsupported("rule %q does not use a private secret", rule.Name)
			}
			if err := validatePort("remote port", rule.Exposure.RemotePort); err != nil {
				return err
			}
			if len(rule.Exposure.CustomDomains) != 0 {
				return unsupported("rule %q is not a domain rule", rule.Name)
			}
			portKey := fmt.Sprintf("%s:%d", rule.Type, rule.Exposure.RemotePort)
			if other, exists := ports[portKey]; exists {
				return unsupported("rules %q and %q both use %s remote port %d", other, rule.Name, strings.ToUpper(rule.Type), rule.Exposure.RemotePort)
			}
			ports[portKey] = rule.Name
		case "stcp", "sudp", "xtcp":
			if rule.Type == "xtcp" && (rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self") {
				return dependencyIsolationError("XTCP rule %q cannot use a TLAN Mesh target in the same process group; create a dedicated non-Mesh XTCP profile", rule.Name)
			}
			if rule.SecretRef == "" || !identifierValid(rule.SecretRef) {
				return unsupported("rule %q private secretRef is invalid", rule.Name)
			}
			if !emptyExposure(rule.Exposure) {
				return unsupported("rule %q private rules do not use public exposure fields", rule.Name)
			}
		case "http", "https", "tcpmux":
			if rule.SecretRef != "" {
				return unsupported("rule %q does not use a private secret", rule.Name)
			}
			if rule.Exposure.Subdomain != "" {
				hasSubdomain = true
			}
			if rule.Exposure.RemotePort != 0 {
				return unsupported("rule %q uses custom domains instead of remotePort", rule.Name)
			}
			if err := validateDomainExposure(rule, &domains); err != nil {
				return err
			}
			if rule.Type == "tcpmux" && rule.Exposure.Multiplexer != "" && rule.Exposure.Multiplexer != "httpconnect" {
				return unsupported("tcpmux rule %q multiplexer must be httpconnect", rule.Name)
			}
			if rule.Type == "tcpmux" && (rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self") {
				return dependencyIsolationError("tcpmux rule %q cannot use a TLAN Mesh target in the same process group; create a dedicated non-Mesh tcpmux profile", rule.Name)
			}
		}
	}
	if hasSubdomain && strings.TrimSpace(cfg.Profile.Server.SubdomainHost) == "" {
		return unsupported("subdomain rules require server.subdomainHost")
	}
	if hasMeshTarget && cfg.Profile.Server.Kind != "managed" {
		return unsupported("Mesh target rules require server.kind = managed and a server-issued grant")
	}
	if hasMeshTarget && hasIndependentTarget {
		return unsupported("Mesh target rules must use a dedicated profile so dependency failure cannot stop independent FRP rules")
	}
	visitorIDs := make(map[string]struct{}, len(cfg.Profile.Visitors))
	visitorNames := make(map[string]struct{}, len(cfg.Profile.Visitors))
	visitorBinds := make(map[string]string, len(cfg.Profile.Visitors))
	for _, visitor := range cfg.Profile.Visitors {
		if !identifierValid(visitor.ID) {
			return unsupported("visitor id %q is invalid", visitor.ID)
		}
		if _, exists := visitorIDs[visitor.ID]; exists {
			return unsupported("duplicate visitor id %q", visitor.ID)
		}
		visitorIDs[visitor.ID] = struct{}{}
		if err := validateName("visitor name", visitor.Name); err != nil {
			return err
		}
		nameKey := strings.ToLower(visitor.Name)
		if _, exists := visitorNames[nameKey]; exists {
			return unsupported("duplicate visitor name %q", visitor.Name)
		}
		visitorNames[nameKey] = struct{}{}
		if visitor.Type != "stcp" && visitor.Type != "sudp" && visitor.Type != "xtcp" {
			return unsupported("visitor %q type must be stcp, sudp or xtcp", visitor.Name)
		}
		if !validFRPName(visitor.ServerName) {
			return unsupported("visitor %q serverName is invalid", visitor.Name)
		}
		if visitor.ServerUser != "" && !validFRPName(visitor.ServerUser) {
			return unsupported("visitor %q serverUser is invalid", visitor.Name)
		}
		if visitor.SecretRef == "" || !identifierValid(visitor.SecretRef) {
			return unsupported("visitor %q secretRef is invalid", visitor.Name)
		}
		if visitor.BindAddr != "127.0.0.1" {
			return unsupported("visitor %q bindAddr must be exactly 127.0.0.1", visitor.Name)
		}
		if err := validatePort("visitor bind port", visitor.BindPort); err != nil {
			return err
		}
		if visitor.Type == "xtcp" {
			if visitor.Protocol != "" && visitor.Protocol != "kcp" && visitor.Protocol != "quic" {
				return unsupported("visitor %q XTCP protocol must be kcp or quic", visitor.Name)
			}
			if visitor.MaxRetriesAnHour != 0 && (visitor.MaxRetriesAnHour < 1 || visitor.MaxRetriesAnHour > 1000) {
				return unsupported("visitor %q maxRetriesAnHour must be between 1 and 1000", visitor.Name)
			}
			if visitor.MinRetryInterval != 0 && (visitor.MinRetryInterval < 1 || visitor.MinRetryInterval > 3600) {
				return unsupported("visitor %q minRetryInterval must be between 1 and 3600 seconds", visitor.Name)
			}
			if visitor.FallbackTimeoutMs != 0 && (visitor.FallbackTimeoutMs < 1 || visitor.FallbackTimeoutMs > 60000) {
				return unsupported("visitor %q fallbackTimeoutMs must be between 1 and 60000", visitor.Name)
			}
			if visitor.FallbackTo != "" && !validFRPName(visitor.FallbackTo) {
				return unsupported("visitor %q fallbackTo is invalid", visitor.Name)
			}
		} else if visitor.Protocol != "" || visitor.KeepTunnelOpen || visitor.MaxRetriesAnHour != 0 ||
			visitor.MinRetryInterval != 0 || visitor.FallbackTo != "" || visitor.FallbackTimeoutMs != 0 {
			return unsupported("visitor %q XTCP-only fields are set for type %s", visitor.Name, strings.ToUpper(visitor.Type))
		}
		bindKey := visitor.Type + ":" + fmt.Sprint(visitor.BindPort)
		if other, exists := visitorBinds[bindKey]; exists {
			return unsupported("visitors %q and %q both use %s bind port %d", other, visitor.Name, strings.ToUpper(visitor.Type), visitor.BindPort)
		}
		visitorBinds[bindKey] = visitor.Name
	}
	if hasMeshTarget && len(cfg.Profile.Visitors) > 0 {
		return dependencyIsolationError("Mesh target rules and independent STCP/SUDP/XTCP visitors are present in one profile; create a dedicated visitor profile so a Mesh failure cannot stop unrelated visitors")
	}
	if isLoopbackHost(cfg.Profile.Server.Host) {
		for _, rule := range cfg.Profile.Rules {
			if !rule.Enabled || (rule.Type != "tcp" && rule.Type != "udp") {
				continue
			}
			if rule.Target.Port == rule.Exposure.RemotePort {
				return reservedTargetError("rule %q targets local port %d while the local FRPS publishes the same port %d; this creates a self-referential public entry", rule.Name, rule.Target.Port, rule.Exposure.RemotePort)
			}
		}
	}
	reservationsToCheck := append([]TargetReservation(nil), fixedTargetReservations...)
	reservationsToCheck = append(reservationsToCheck, configTargetReservations(cfg.Profile.Server)...)
	reservationsToCheck = append(reservationsToCheck, reservations...)
	if err := validateTargetReservations(cfg, reservationsToCheck); err != nil {
		return err
	}
	return nil
}

func dependencyIsolationError(format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return &Error{Code: CodeUnsupportedFeature, Err: fmt.Errorf("%w: %s", ErrDependencyIsolation, detail)}
}

func reservedTargetError(format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return &Error{Code: CodeUnsupportedFeature, Err: fmt.Errorf("%w: %s", ErrReservedTarget, detail)}
}

func validateAllowUsers(rule Rule) error {
	if len(rule.Exposure.AllowUsers) == 0 {
		return nil
	}
	switch rule.Type {
	case "stcp", "sudp", "xtcp":
	default:
		return unsupported("rule %q allowUsers is only supported for STCP, SUDP and XTCP", rule.Name)
	}
	if len(rule.Exposure.AllowUsers) > MaxAllowUsers {
		return unsupported("rule %q supports at most %d allowUsers entries", rule.Name, MaxAllowUsers)
	}
	for _, user := range rule.Exposure.AllowUsers {
		if !validAllowUser(user) {
			return unsupported("rule %q allowUsers entry %q is invalid", rule.Name, user)
		}
	}
	return nil
}

func validAllowUser(value string) bool {
	return value == "*" || validFRPName(value)
}

func emptyExposure(exposure Exposure) bool {
	return exposure.RemotePort == 0 && len(exposure.CustomDomains) == 0 && exposure.Subdomain == "" &&
		len(exposure.Locations) == 0 && exposure.HTTPUser == "" && exposure.HTTPPasswordRef == "" &&
		exposure.HostHeaderRewrite == "" && exposure.RouteByHTTPUser == "" &&
		len(exposure.RequestHeaders) == 0 && len(exposure.ResponseHeaders) == 0 && exposure.Multiplexer == ""
}

func validateDomainExposure(rule Rule, domains *map[string]string) error {
	exposure := rule.Exposure
	if len(exposure.CustomDomains) > MaxDomains {
		return unsupported("rule %q supports at most %d custom domains", rule.Name, MaxDomains)
	}
	if len(exposure.CustomDomains) == 0 && exposure.Subdomain == "" {
		return unsupported("rule %q must have at least one custom domain or subdomain", rule.Name)
	}
	if exposure.Subdomain != "" {
		if err := validateSubdomain(exposure.Subdomain); err != nil {
			return err
		}
		key := "@" + exposure.Subdomain
		if other, exists := (*domains)[key]; exists {
			return unsupported("rules %q and %q both use subdomain %q", other, rule.Name, exposure.Subdomain)
		}
		(*domains)[key] = rule.Name
	}
	for _, domain := range exposure.CustomDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if rule.Type == "tcpmux" {
			if err := validateHost("tcpmux domain", domain); err != nil {
				return err
			}
		} else if err := validateDomain(domain); err != nil {
			return err
		}
		if other, exists := (*domains)[domain]; exists {
			return unsupported("rules %q and %q both use domain %q", other, rule.Name, domain)
		}
		(*domains)[domain] = rule.Name
	}
	if exposure.HTTPUser != "" || exposure.HTTPPasswordRef != "" {
		if rule.Type == "https" {
			return unsupported("rule %q HTTPS does not use HTTP basic authentication fields", rule.Name)
		}
		if exposure.HTTPUser == "" || exposure.HTTPPasswordRef == "" {
			return unsupported("rule %q must set both HTTP user and password reference", rule.Name)
		}
		if !validFRPName(exposure.HTTPUser) || !identifierValid(exposure.HTTPPasswordRef) {
			return unsupported("rule %q HTTP authentication fields are invalid", rule.Name)
		}
	}
	if exposure.HostHeaderRewrite != "" {
		if rule.Type != "http" {
			return unsupported("rule %q hostHeaderRewrite is only supported for HTTP rules", rule.Name)
		}
		if err := validateHost("host header rewrite", exposure.HostHeaderRewrite); err != nil {
			return err
		}
	}
	if exposure.RouteByHTTPUser != "" {
		if rule.Type != "http" && rule.Type != "tcpmux" {
			return unsupported("rule %q routeByHTTPUser is only supported for HTTP/tcpmux rules", rule.Name)
		}
		if !validFRPName(exposure.RouteByHTTPUser) {
			return unsupported("rule %q routeByHTTPUser is invalid", rule.Name)
		}
	}
	if rule.Type != "http" {
		if len(exposure.Locations) != 0 || len(exposure.RequestHeaders) != 0 || len(exposure.ResponseHeaders) != 0 {
			return unsupported("rule %q locations/header rewrites are only supported for HTTP rules", rule.Name)
		}
	} else {
		if err := validateLocations(exposure.Locations); err != nil {
			return err
		}
		if err := validateHeaderMap("request headers", exposure.RequestHeaders); err != nil {
			return err
		}
		if err := validateHeaderMap("response headers", exposure.ResponseHeaders); err != nil {
			return err
		}
	}
	return nil
}

func validateSubdomain(value string) error {
	if value == "" || len(value) > 63 || strings.ContainsAny(value, ".*/\x00\r\n\t ") {
		return unsupported("subdomain must be a 1-63 character DNS label without dot, wildcard or whitespace")
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return unsupported("subdomain must not start or end with '-'")
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return unsupported("subdomain may contain only lowercase letters, digits and '-'")
		}
	}
	return nil
}

func validateLocations(locations []string) error {
	if len(locations) > 32 {
		return unsupported("at most 32 HTTP locations are supported")
	}
	for _, location := range locations {
		if location == "" || len(location) > 256 || !strings.HasPrefix(location, "/") ||
			strings.ContainsAny(location, "\x00\r\n\t ") || strings.Contains(location, "..") {
			return unsupported("HTTP location %q is invalid; use an absolute path such as / or /api", location)
		}
	}
	return nil
}

func validateHeaderMap(label string, values map[string]string) error {
	if len(values) > MaxHeaderFields {
		return unsupported("%s supports at most %d fields", label, MaxHeaderFields)
	}
	for name, value := range values {
		if !validHeaderName(name) {
			return unsupported("%s contains invalid header name %q", label, name)
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return unsupported("%s header %q value is invalid", label, name)
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

// IsDependencyIsolationError reports whether a profile violates the visitor
// dependency boundary and must be split into separate profiles.
func IsDependencyIsolationError(err error) bool {
	return errors.Is(err, ErrDependencyIsolation)
}

// IsReservedTargetError reports whether a configured target or listener
// conflicts with a reserved TLAN/FRP endpoint.
func IsReservedTargetError(err error) bool {
	return errors.Is(err, ErrReservedTarget)
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func configTargetReservations(server Server) []TargetReservation {
	if !isLoopbackHost(server.Host) {
		return nil
	}
	return []TargetReservation{
		{Host: "127.0.0.1", Port: server.Port, Purpose: "configured FRPS control listener"},
		{Host: "127.0.0.1", Port: server.PublicHTTPPort, Purpose: "configured FRPS HTTP vhost"},
		{Host: "127.0.0.1", Port: server.PublicHTTPSPort, Purpose: "configured FRPS HTTPS vhost"},
	}
}

func validateTargetReservations(cfg Config, reservations []TargetReservation) error {
	for _, reservation := range reservations {
		host := strings.TrimSpace(reservation.Host)
		reservationAddr, err := netip.ParseAddr(host)
		if err != nil || !reservationAddr.Is4() {
			return unsupported("target reservation must use a literal IPv4 address")
		}
		if err := validatePort("target reservation port", reservation.Port); err != nil {
			return err
		}
		purpose := strings.TrimSpace(reservation.Purpose)
		if purpose == "" {
			purpose = "reserved management endpoint"
		}
		for _, rule := range cfg.Profile.Rules {
			targetAddr, parseErr := netip.ParseAddr(rule.Target.Host)
			if parseErr != nil || !targetAddr.Is4() || targetAddr != reservationAddr || rule.Target.Port != reservation.Port {
				continue
			}
			return reservedTargetError("rule %q targets reserved endpoint %s:%d (%s)", rule.Name, reservationAddr, reservation.Port, purpose)
		}
		for _, visitor := range cfg.Profile.Visitors {
			if visitor.BindAddr != reservationAddr.String() || visitor.BindPort != reservation.Port {
				continue
			}
			if reservation.AllowVisitorBind && cfg.Profile.ID == reservation.OwnerProfileID && visitor.ID == reservation.VisitorID {
				continue
			}
			return reservedTargetError("visitor %q would bind reserved endpoint %s:%d (%s)", visitor.Name, reservationAddr, reservation.Port, purpose)
		}
	}
	return nil
}

func validateTarget(rule Rule) error {
	switch rule.Target.Kind {
	case "loopback":
		if rule.Target.NetworkID != "" || rule.Target.DeviceID != "" || rule.Target.PublicKey != "" {
			return unsupported("rule %q loopback target cannot contain Mesh identity fields", rule.Name)
		}
		if rule.Target.Host != "127.0.0.1" {
			return unsupported("rule %q loopback target must be exactly 127.0.0.1", rule.Name)
		}
	case "mesh_peer", "mesh_self":
		if core.NetworkID(rule.Target.NetworkID).Validate() != nil || core.DeviceID(rule.Target.DeviceID).Validate() != nil {
			return unsupported("rule %q mesh target identity is invalid", rule.Name)
		}
		if rule.Target.Kind == "mesh_peer" && !identifierValid(rule.Target.ServiceID) {
			return unsupported("rule %q mesh_peer target service ID is required", rule.Name)
		}
		if rule.Target.ServiceID != "" && !identifierValid(rule.Target.ServiceID) {
			return unsupported("rule %q mesh target service ID is invalid", rule.Name)
		}
		addr, err := netip.ParseAddr(rule.Target.Host)
		if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			return unsupported("rule %q mesh target must be a literal Mesh IPv4 address", rule.Name)
		}
		if err := validateTargetAddressPolicy(rule, addr); err != nil {
			return err
		}
		if !isTLANMeshAddress(addr) {
			return unsupported("rule %q mesh target must be inside the TLAN pools 10.0.0.0/8 or 100.64.0.0/10", rule.Name)
		}

		if rule.Target.PublicKey != "" {
			if err := core.ValidateWireGuardPublicKey(rule.Target.PublicKey); err != nil {
				return unsupported("rule %q mesh target public key is invalid", rule.Name)
			}
		}
	case "lan":
		if rule.Target.NetworkID != "" || rule.Target.DeviceID != "" || rule.Target.PublicKey != "" {
			return unsupported("rule %q LAN target cannot contain Mesh identity fields", rule.Name)
		}
		addr, err := netip.ParseAddr(rule.Target.Host)
		if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalMulticast() {
			return unsupported("rule %q LAN target must be a unicast IPv4 address", rule.Name)
		}
		if err := validateTargetAddressPolicy(rule, addr); err != nil {
			return err
		}
		if !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
			return unsupported("rule %q LAN target must be a private or link-local IPv4 address", rule.Name)
		}
	default:
		return unsupported("rule %q target kind must be loopback, lan, mesh_peer or mesh_self", rule.Name)
	}
	return nil
}

func validateTargetAddressPolicy(rule Rule, addr netip.Addr) error {
	if purpose, reserved := reservedTargetAddresses[addr]; reserved {
		return reservedTargetError("rule %q targets reserved address %s (%s)", rule.Name, addr, purpose)
	}
	return nil
}

func isTLANMeshAddress(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, pool := range tlanMeshPools {
		if pool.Contains(addr) {
			return true
		}
	}
	return false
}

func validTLANMembershipPrefix(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 30 {
		return false
	}
	for _, pool := range tlanMeshPools {
		if prefix.Bits() >= pool.Bits() && pool.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return netip.Addr{}
	}
	bytes := prefix.Masked().Addr().As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	hostBits := 32 - prefix.Bits()
	if hostBits <= 0 || hostBits >= 32 {
		return prefix.Masked().Addr()
	}
	value |= (uint32(1) << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// ValidateMeshTargetPolicy verifies Mesh rules against the current membership
// context and the actual TLAN network prefix. ValidateConfig alone cannot know
// which members exist or which prefix is currently active, so the runtime must
// call this before starting or applying Mesh-dependent rules.
func ValidateMeshTargetPolicy(cfg Config, localNetworkID, localDeviceID string, networkPrefix netip.Prefix) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	hasMesh := false
	for _, rule := range cfg.Profile.Rules {
		if rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self" {
			hasMesh = true
			break
		}
	}
	if !hasMesh {
		return nil
	}
	if core.NetworkID(localNetworkID).Validate() != nil {
		return codedError(CodeAuthRejected, "current TLAN network identity is invalid")
	}
	if core.DeviceID(localDeviceID).Validate() != nil {
		return codedError(CodeAuthRejected, "current TLAN device identity is invalid")
	}
	prefix := networkPrefix.Masked()
	if !validTLANMembershipPrefix(prefix) {
		return unsupported("active TLAN network prefix must be a /30 or larger IPv4 prefix inside 10.0.0.0/8 or 100.64.0.0/10")
	}
	first := prefix.Addr()
	last := prefixLastAddr(prefix)
	for _, rule := range cfg.Profile.Rules {
		if rule.Target.Kind != "mesh_peer" && rule.Target.Kind != "mesh_self" {
			continue
		}
		if rule.Target.NetworkID != localNetworkID {
			return codedError(CodeAuthRejected, "rule %q targets network %q instead of the active network %q", rule.Name, rule.Target.NetworkID, localNetworkID)
		}
		switch rule.Target.Kind {
		case "mesh_peer":
			if rule.Target.DeviceID == localDeviceID {
				return codedError(CodeAuthRejected, "rule %q uses mesh_peer for the local device; use mesh_self instead", rule.Name)
			}
		case "mesh_self":
			if rule.Target.DeviceID != localDeviceID {
				return codedError(CodeAuthRejected, "rule %q mesh_self target %q is not the local device %q", rule.Name, rule.Target.DeviceID, localDeviceID)
			}
		}
		addr, err := netip.ParseAddr(rule.Target.Host)
		if err != nil {
			return unsupported("rule %q mesh target address is invalid", rule.Name)
		}
		if err := validateTargetAddressPolicy(rule, addr); err != nil {
			return err
		}
		if !prefix.Contains(addr) {
			return codedError(CodeRouteConflict, "rule %q target %s is outside the active TLAN prefix %s", rule.Name, addr, prefix)
		}
		if addr == first || addr == last {
			return unsupported("rule %q mesh target %s is the network or broadcast address", rule.Name, addr)
		}
	}
	return nil
}

func ValidateServer(server Server) error {
	if server.Kind != "private_token" && server.Kind != "managed" {
		return unsupported("server kind must be private_token or managed")
	}
	if err := validateHost("server host", server.Host); err != nil {
		return err
	}
	if ip := net.ParseIP(server.Host); ip != nil && ip.To4() == nil {
		return unsupported("IPv6 FRP server addresses are not supported by this TLAN profile")
	}
	if err := validatePort("server port", server.Port); err != nil {
		return err
	}
	switch server.Transport {
	case "tcp", "websocket", "wss", "quic", "kcp":
	default:
		return unsupported("server transport must be tcp, websocket, wss, quic or kcp")
	}
	if server.TLSServerName == "" {
		return unsupported("TLS serverName is required; insecure certificate verification is never enabled")
	}
	if err := validateHost("TLS serverName", server.TLSServerName); err != nil {
		return err
	}
	if server.TrustedCAPath == "" {
		if !server.UseSystemCA {
			return unsupported("a trusted CA file is required; insecure certificate verification is never enabled")
		}
	} else if !filepath.IsAbs(server.TrustedCAPath) {
		return unsupported("trusted CA path must be absolute")
	}
	if server.CredentialRef == "" || !identifierValid(server.CredentialRef) {
		return unsupported("credentialRef is invalid")
	}
	if server.Kind == "managed" && (server.ServerID == "" || !identifierValid(server.ServerID)) {
		return unsupported("managed serverId is invalid")
	}
	if server.Kind == "private_token" && server.ServerID != "" {
		return unsupported("private_token serverId must be empty")
	}
	if err := validatePort("public HTTP port", server.PublicHTTPPort); err != nil {
		return err
	}
	if err := validatePort("public HTTPS port", server.PublicHTTPSPort); err != nil {
		return err
	}
	if err := validatePort("public TCPMUX port", server.PublicTCPMuxPort); err != nil {
		return err
	}
	if server.SubdomainHost != "" {
		if err := validateHost("subdomain host", server.SubdomainHost); err != nil {
			return err
		}
		if net.ParseIP(server.SubdomainHost) != nil || !strings.Contains(server.SubdomainHost, ".") {
			return unsupported("subdomain host must be a fully qualified DNS name")
		}
	}
	return nil
}

func ValidateRunInputs(cfg Config, token string) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if token == "" {
		return codedError(CodeAuthRejected, "FRP token is not configured")
	}
	if len(token) > MaxTokenBytes {
		return codedError(CodeAuthRejected, "FRP token exceeds %d bytes", MaxTokenBytes)
	}
	if strings.ContainsAny(token, "\x00\r\n") {
		return codedError(CodeAuthRejected, "FRP token contains an invalid control character")
	}
	if cfg.Profile.Server.TrustedCAPath != "" || !cfg.Profile.Server.UseSystemCA {
		if err := ValidateCAFile(cfg.Profile.Server.TrustedCAPath); err != nil {
			return withCode(CodeTLSUntrusted, err)
		}
	}
	return nil
}

func ValidateCAFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read trusted CA: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("trusted CA is not a regular file")
	}
	if info.Size() <= 0 || info.Size() > MaxCABytes {
		return fmt.Errorf("trusted CA size must be between 1 and %d bytes", MaxCABytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read trusted CA: %w", err)
	}
	return ValidateCAPEM(data)
}

// ValidateCAPEM verifies PEM certificate contents without reading from disk.
func ValidateCAPEM(data []byte) error {
	if len(data) == 0 || len(data) > MaxCABytes {
		return fmt.Errorf("trusted CA size must be between 1 and %d bytes", MaxCABytes)
	}
	var rest = data
	var parsed int
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("trusted CA contains unexpected PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("parse trusted CA certificate: %w", err)
		}
		parsed++
	}
	if parsed == 0 {
		return errors.New("trusted CA file contains no X.509 certificates")
	}
	return nil
}

func validatePort(label string, port int) error {
	if port < 1 || port > 65535 {
		return unsupported("%s must be between 1 and 65535", label)
	}
	return nil
}

func validateName(label, value string) error {
	if value == "" {
		return unsupported("%s is required", label)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 {
		return unsupported("%s must be at most 64 UTF-8 characters", label)
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\uFFFD' {
			return unsupported("%s contains an invalid character", label)
		}
	}
	return nil
}

func validateHost(label, value string) error {
	if value == "" {
		return unsupported("%s is required", label)
	}
	if len(value) > 253 || strings.ContainsAny(value, "/\\@?#[]") || strings.ContainsAny(value, "\x00\r\n\t ") {
		return unsupported("%s is invalid", label)
	}
	if ip := net.ParseIP(value); ip != nil {
		return nil
	}
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || len(value) > 253 {
		return unsupported("%s is invalid", label)
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return unsupported("%s is invalid", label)
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return unsupported("%s is invalid", label)
			}
		}
	}
	return nil
}

func validateDomain(value string) error {
	if err := validateHost("custom domain", value); err != nil {
		return err
	}
	if net.ParseIP(value) != nil {
		return unsupported("custom domain %q must not be an IP address", value)
	}
	if !strings.Contains(value, ".") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return unsupported("custom domain %q must be a fully qualified DNS name", value)
	}
	return nil
}

func validFRPName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}
