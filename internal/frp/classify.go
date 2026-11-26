package frp

import "strings"

func classifyStartupError(message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "FRP process stopped without an error message"
	}
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "certificate") || strings.Contains(lower, "x509") ||
		strings.Contains(lower, "unknown authority") || strings.Contains(lower, "tls: failed") ||
		strings.Contains(lower, "server name") && strings.Contains(lower, "tls"):
		return codedError(CodeTLSUntrusted, "%s", message)
	case strings.Contains(lower, "frp_lease_revoked") || strings.Contains(lower, "frp_lease_expired") ||
		strings.Contains(lower, "frp_auth_rejected") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "authentication") || strings.Contains(lower, "authorization failed") ||
		strings.Contains(lower, "login failed") || strings.Contains(lower, "invalid login"):
		return codedError(CodeAuthRejected, "%s", message)
	case strings.Contains(lower, "mesh_dependency_down") || strings.Contains(lower, "target gateway") ||
		strings.Contains(lower, "mesh lease"):
		return codedError(CodeMeshDependencyDown, "%s", message)
	case strings.Contains(lower, "port not allowed") || strings.Contains(lower, "not allowed") ||
		strings.Contains(lower, "allowports") || strings.Contains(lower, "port range") ||
		strings.Contains(lower, "port denied") || strings.Contains(lower, "not in allowed"):
		return codedError(CodeRemotePortDenied, "%s", message)
	case strings.Contains(lower, "port already used") || strings.Contains(lower, "already used") ||
		strings.Contains(lower, "port is occupied") || strings.Contains(lower, "port occupied") ||
		strings.Contains(lower, "port unavailable") || strings.Contains(lower, "remote_port is already leased") ||
		strings.Contains(lower, "already leased"):
		return codedError(CodeRemotePortBusy, "%s", message)
	case strings.Contains(lower, "bind") && (strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "only one usage")):
		return codedError(CodeLocalListenBusy, "%s", message)
	case strings.Contains(lower, "dial tcp 127.0.0.1") || strings.Contains(lower, "connectex") &&
		strings.Contains(lower, "127.0.0.1"):
		return codedError(CodeBackendUnreachable, "%s", message)
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "connectex") ||
		strings.Contains(lower, "no such host") || strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "network is unreachable"):
		return codedError(CodeServerUnreachable, "%s", message)
	default:
		return codedError(CodeProcessFailed, "%s", message)
	}
}

func classifyProxyError(message string) error {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lower, "port already used") || strings.Contains(lower, "already used") ||
		strings.Contains(lower, "port unavailable") || strings.Contains(lower, "port is occupied") ||
		strings.Contains(lower, "port occupied") || strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "only one usage") || strings.Contains(lower, "remote_port is already leased") ||
		strings.Contains(lower, "already leased") || strings.Contains(lower, "already exists"):
		return codedError(CodeRemotePortBusy, "%s", trimmed)
	case strings.Contains(lower, "port not allowed") || strings.Contains(lower, "not allowed") ||
		strings.Contains(lower, "allowports") || strings.Contains(lower, "port range") ||
		strings.Contains(lower, "port denied") || strings.Contains(lower, "frp_port_denied"):
		return codedError(CodeRemotePortDenied, "%s", trimmed)
	}
	return classifyStartupError(trimmed)
}

func classifyLeaseAcquireError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "remote_port is already leased") || strings.Contains(lower, "already leased") ||
		strings.Contains(lower, "port already used") || strings.Contains(lower, "port occupied") ||
		strings.Contains(lower, "port unavailable"):
		return withCode(CodeRemotePortBusy, err)
	case strings.Contains(lower, "port denied") || strings.Contains(lower, "port not allowed") ||
		strings.Contains(lower, "not in allowed") || strings.Contains(lower, "allowports") ||
		strings.Contains(lower, "port range"):
		return withCode(CodeRemotePortDenied, err)
	default:
		return withCode(CodeAuthRejected, err)
	}
}

func terminalStartupLog(message string) bool {
	lower := strings.ToLower(message)
	for _, marker := range []string{
		"login to server failed",
		"authentication failed",
		"invalid token",
		"token in login",
		"certificate signed by unknown authority",
		"x509:",
		"unknown authority",
		"frp_lease_revoked",
		"frp_lease_expired",
		"frp_auth_rejected",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
