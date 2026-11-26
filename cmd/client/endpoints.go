package main

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

const defaultServerURL = ""
const defaultSTUNPort = "3478"

// Public deployment settings, never administrator credentials. These variables
// remain overridable with the build script's -ldflags options.
var bundledServerURL = defaultServerURL
var bundledSTUNAddress = ""

func normalizeServerURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("服务器地址不能为空 / Server address is required")
	}
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return "", errors.New("服务器地址不能包含空白字符 / Server address must not contain spaces")
	}
	if !strings.Contains(value, "://") {
		host, port, err := net.SplitHostPort(value)
		if err != nil || strings.TrimSpace(host) == "" || strings.ContainsAny(host, "/?#@") {
			return "", errors.New("请输入服务器 IP:端口（如 203.0.113.10:8443）或完整 HTTP(S) 地址 / Enter host:port or HTTP(S) URL")
		}
		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNum == 0 {
			return "", errors.New("服务器端口必须在 1 到 65535 之间 / Port must be 1-65535")
		}
		value = "https://" + net.JoinHostPort(host, strconv.FormatUint(portNum, 10))
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", errors.New("服务器地址格式不正确 / Invalid server URL format")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("服务器地址必须是 IP:端口 或 HTTP(S) 地址 / Must be host:port or HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("服务器地址只能包含协议、主机和端口 / URL must only contain scheme, host, and port")
	}
	return u.Scheme + "://" + u.Host, nil
}

func displayServerEndpoint(serverURL string) string {
	trimmed := strings.TrimSpace(serverURL)
	if trimmed == "" {
		return ""
	}
	normalized, err := normalizeServerURL(trimmed)
	if err != nil {
		return trimmed
	}
	if strings.HasPrefix(normalized, "https://") {
		return strings.TrimPrefix(normalized, "https://")
	}
	return normalized
}

func hostFromServerURL(serverURL string) string {
	normalized, err := normalizeServerURL(serverURL)
	if err != nil {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func STUNAddressForServer(serverURL string) (string, error) {
	normalized, err := normalizeServerURL(serverURL)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(u.Hostname(), defaultSTUNPort), nil
}

func connectionEndpoints(serverValue, stunValue string) (string, string, error) {
	server, err := normalizeServerURL(serverValue)
	if err != nil {
		return "", "", err
	}
	stunValue = strings.TrimSpace(stunValue)
	if stunValue == "" {
		stun, err := STUNAddressForServer(server)
		return server, stun, err
	}
	host, port, err := net.SplitHostPort(stunValue)
	if err != nil || strings.TrimSpace(host) == "" || strings.ContainsFunc(host, unicode.IsSpace) {
		return "", "", errors.New("STUN 地址必须是主机:端口 / STUN address must be host:port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", "", errors.New("STUN 端口必须在 1 到 65535 之间 / STUN port must be 1-65535")
	}
	return server, net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), nil
}

func savedCredentialsForServer(settings clientidentity.Settings, base string) (string, string) {
	saved, err := normalizeServerURL(settings.ServerURL)
	if err != nil {
		return "", ""
	}
	base, err = normalizeServerURL(base)
	if err != nil || saved != base {
		return "", ""
	}
	token := ""
	if strings.HasPrefix(settings.Token, "member_") {
		token = settings.Token
	}
	return token, strings.TrimSpace(settings.AdminToken)
}

func startupServer(saved, flagValue string, explicitlySet bool) string {
	if explicitlySet {
		return strings.TrimSpace(flagValue)
	}
	if saved = strings.TrimSpace(saved); saved != "" {
		return saved
	}
	return strings.TrimSpace(flagValue)
}

func migrateBundledSettings(settings clientidentity.Settings, _ string) clientidentity.Settings {
	return settings
}
