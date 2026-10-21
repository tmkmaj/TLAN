package frp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ImportIssue describes a field that the restricted import schema will not
// accept. Dangerous fields are reported separately from merely unsupported
// fields so the UI can explain why a profile cannot be imported.
type ImportIssue struct {
	Path      string
	Reason    string
	Dangerous bool
}

type ImportChangeSet struct {
	Added       int
	Removed     int
	Modified    int
	AddedIDs    []string
	RemovedIDs  []string
	ModifiedIDs []string
}

type ImportServerChange struct {
	Changed bool
	Fields  []string
}

// ImportAnalysis is a pure preview of a candidate restricted JSON profile.
// Config is populated only when Supported is true.
type ImportAnalysis struct {
	Supported       bool
	Config          Config
	Issues          []ImportIssue
	ValidationError string
	Rules           ImportChangeSet
	Visitors        ImportChangeSet
	Server          ImportServerChange
}

type importFieldKind uint8

const (
	importScalar importFieldKind = iota
	importProfile
	importServer
	importRulesArray
	importVisitorsArray
	importRule
	importTarget
	importExposure
	importTransport
	importStringArray
	importStringMap
)

var (
	importConfigFields = map[string]importFieldKind{
		"schemaVersion": importScalar,
		"profile":       importProfile,
	}
	importProfileFields = map[string]importFieldKind{
		"id": importScalar, "name": importScalar, "coreVersion": importScalar,
		"revision": importScalar, "server": importServer,
		"rules": importRulesArray, "visitors": importVisitorsArray,
	}
	importServerFields = map[string]importFieldKind{
		"kind": importScalar, "host": importScalar, "port": importScalar,
		"transport": importScalar, "tlsServerName": importScalar,
		"trustedCAPath": importScalar, "credentialRef": importScalar,
		"serverId": importScalar, "publicHttpPort": importScalar,
		"publicHttpsPort": importScalar, "publicTcpMuxPort": importScalar,
		"subdomainHost": importScalar, "tcpMux": importScalar,
		"disableCustomTLSFirstByte": importScalar,
	}
	importRuleFields = map[string]importFieldKind{
		"id": importScalar, "name": importScalar, "type": importScalar,
		"enabled": importScalar, "secretRef": importScalar,
		"target": importTarget, "exposure": importExposure,
		"transport": importTransport,
	}
	importTargetFields = map[string]importFieldKind{
		"kind": importScalar, "host": importScalar, "port": importScalar,
		"networkId": importScalar, "deviceId": importScalar,
		"publicKey": importScalar, "serviceId": importScalar,
	}
	importExposureFields = map[string]importFieldKind{
		"remotePort": importScalar, "customDomains": importStringArray,
		"subdomain": importScalar, "locations": importStringArray,
		"allowUsers": importStringArray, "httpUser": importScalar,
		"httpPasswordRef": importScalar, "hostHeaderRewrite": importScalar,
		"routeByHTTPUser": importScalar, "requestHeaders": importStringMap,
		"responseHeaders": importStringMap, "multiplexer": importScalar,
	}
	importTransportFields = map[string]importFieldKind{
		"useEncryption": importScalar, "useCompression": importScalar,
		"proxyProtocolVersion": importScalar,
	}
	importVisitorFields = map[string]importFieldKind{
		"id": importScalar, "name": importScalar, "type": importScalar,
		"enabled": importScalar, "serverName": importScalar,
		"serverUser": importScalar, "secretRef": importScalar,
		"bindAddr": importScalar, "bindPort": importScalar,
		"protocol": importScalar, "keepTunnelOpen": importScalar,
		"maxRetriesAnHour": importScalar, "minRetryInterval": importScalar,
		"fallbackTo": importScalar, "fallbackTimeoutMs": importScalar,
	}
)

// AnalyzeConfigImport parses only the restricted TLAN JSON schema. It never
// accepts TOML, raw frpc configuration, plugins, or unknown JSON fields.
func AnalyzeConfigImport(data []byte, current *Config) (ImportAnalysis, error) {
	if len(data) == 0 {
		return ImportAnalysis{}, fmt.Errorf("配置文件不能为空")
	}
	if len(data) > MaxConfigBytes {
		return ImportAnalysis{}, fmt.Errorf("配置文件不能超过 %d 字节", MaxConfigBytes)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return ImportAnalysis{}, fmt.Errorf("仅支持 TLAN 受限 JSON 配置，不接受 TOML 或其他格式: %w", err)
	}
	issues := inspectImportObject("", data, importConfigFields)
	analysis := ImportAnalysis{Issues: issues}
	if len(issues) != 0 {
		return analysis, nil
	}
	imported, err := DecodeConfig(bytes.NewReader(data))
	if err != nil {
		analysis.ValidationError = err.Error()
		return analysis, nil
	}
	analysis.Supported = true
	analysis.Config = imported

	if current == nil {
		analysis.Rules = addedRules(imported.Profile.Rules)
		analysis.Visitors = addedVisitors(imported.Profile.Visitors)
		analysis.Server = ImportServerChange{Changed: true, Fields: []string{"首次导入"}}
		return analysis, nil
	}
	before := NormalizeConfig(CloneConfig(*current))
	after := NormalizeConfig(CloneConfig(imported))
	analysis.Rules = diffRules(before.Profile.Rules, after.Profile.Rules)
	analysis.Visitors = diffVisitors(before.Profile.Visitors, after.Profile.Visitors)
	analysis.Server = diffServer(before.Profile.Server, after.Profile.Server)
	return analysis, nil
}

func (a ImportAnalysis) RejectText() string {
	lines := make([]string, 0, len(a.Issues)+1)
	if a.ValidationError != "" {
		lines = append(lines, "配置校验失败："+a.ValidationError)
	}
	for _, issue := range a.Issues {
		prefix := "不支持字段"
		if issue.Dangerous {
			prefix = "危险字段"
		}
		lines = append(lines, fmt.Sprintf("- %s：%s（%s）", issue.Path, prefix, issue.Reason))
	}
	if len(lines) == 0 {
		return "配置未通过受限导入检查"
	}
	return strings.Join(lines, "\n")
}

func (a ImportAnalysis) PreviewText() string {
	server := "无变化"
	if a.Server.Changed {
		server = strings.Join(a.Server.Fields, "、")
		if server == "" {
			server = "有变化"
		}
	}
	return fmt.Sprintf("规则：新增 %d，删除 %d，修改 %d\n服务器变化：%s\n访客：新增 %d，删除 %d，修改 %d",
		a.Rules.Added, a.Rules.Removed, a.Rules.Modified, server,
		a.Visitors.Added, a.Visitors.Removed, a.Visitors.Modified)
}

func inspectImportObject(path string, raw json.RawMessage, fields map[string]importFieldKind) []ImportIssue {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return []ImportIssue{{Path: pathOrRoot(path), Reason: "应为 JSON 对象"}}
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	issues := make([]ImportIssue, 0)
	for _, key := range keys {
		fieldPath := key
		if path != "" {
			fieldPath = path + "." + key
		}
		kind, known := fields[key]
		if !known {
			issues = append(issues, ImportIssue{
				Path:      fieldPath,
				Reason:    unsupportedImportReason(key),
				Dangerous: dangerousImportField(key),
			})
			continue
		}
		issues = append(issues, inspectImportValue(fieldPath, kind, object[key])...)
	}
	return issues
}

func inspectImportValue(path string, kind importFieldKind, raw json.RawMessage) []ImportIssue {
	switch kind {
	case importProfile:
		return inspectImportObject(path, raw, importProfileFields)
	case importServer:
		return inspectImportObject(path, raw, importServerFields)
	case importRulesArray:
		return inspectImportArray(path, raw, importRuleFields)
	case importVisitorsArray:
		return inspectImportArray(path, raw, importVisitorFields)
	case importRule:
		return inspectImportObject(path, raw, importRuleFields)
	case importTarget:
		return inspectImportObject(path, raw, importTargetFields)
	case importExposure:
		return inspectImportObject(path, raw, importExposureFields)
	case importTransport:
		return inspectImportObject(path, raw, importTransportFields)
	case importStringArray, importStringMap, importScalar:
		return nil
	default:
		return nil
	}
}

func inspectImportArray(path string, raw json.RawMessage, fields map[string]importFieldKind) []ImportIssue {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return []ImportIssue{{Path: path, Reason: "应为 JSON 数组"}}
	}
	issues := make([]ImportIssue, 0)
	for i, item := range items {
		issues = append(issues, inspectImportObject(fmt.Sprintf("%s[%d]", path, i), item, fields)...)
	}
	return issues
}

func pathOrRoot(path string) string {
	if path == "" {
		return "<root>"
	}
	return path
}

func unsupportedImportReason(key string) string {
	if dangerousImportField(key) {
		return "不接受令牌、密码、私钥、直连 URL、管理面或执行配置"
	}
	return "固定导入 schema 不支持该字段"
}

func dangerousImportField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	switch normalized {
	case "auth", "token", "tokensource", "tokenfile", "secret", "secretkey", "privatekey",
		"password", "httppassword", "proxyurl", "webserver", "admin", "adminport",
		"plugin", "plugins", "exec", "execute", "command", "args", "metadatas", "metadata",
		"serveraddr", "serverport", "trustedcafile":
		return true
	default:
		return false
	}
}

func diffRules(before, after []Rule) ImportChangeSet {
	beforeMap := make(map[string]Rule, len(before))
	afterMap := make(map[string]Rule, len(after))
	for _, rule := range before {
		beforeMap[rule.ID] = rule
	}
	for _, rule := range after {
		afterMap[rule.ID] = rule
	}
	var changes ImportChangeSet
	for id, rule := range afterMap {
		old, ok := beforeMap[id]
		switch {
		case !ok:
			changes.AddedIDs = append(changes.AddedIDs, id)
		case !reflect.DeepEqual(old, rule):
			changes.ModifiedIDs = append(changes.ModifiedIDs, id)
		}
	}
	for id := range beforeMap {
		if _, ok := afterMap[id]; !ok {
			changes.RemovedIDs = append(changes.RemovedIDs, id)
		}
	}
	sort.Strings(changes.AddedIDs)
	sort.Strings(changes.RemovedIDs)
	sort.Strings(changes.ModifiedIDs)
	changes.Added = len(changes.AddedIDs)
	changes.Removed = len(changes.RemovedIDs)
	changes.Modified = len(changes.ModifiedIDs)
	return changes
}

func diffVisitors(before, after []Visitor) ImportChangeSet {
	beforeMap := make(map[string]Visitor, len(before))
	afterMap := make(map[string]Visitor, len(after))
	for _, visitor := range before {
		beforeMap[visitor.ID] = visitor
	}
	for _, visitor := range after {
		afterMap[visitor.ID] = visitor
	}
	var changes ImportChangeSet
	for id, visitor := range afterMap {
		old, ok := beforeMap[id]
		switch {
		case !ok:
			changes.AddedIDs = append(changes.AddedIDs, id)
		case !reflect.DeepEqual(old, visitor):
			changes.ModifiedIDs = append(changes.ModifiedIDs, id)
		}
	}
	for id := range beforeMap {
		if _, ok := afterMap[id]; !ok {
			changes.RemovedIDs = append(changes.RemovedIDs, id)
		}
	}
	sort.Strings(changes.AddedIDs)
	sort.Strings(changes.RemovedIDs)
	sort.Strings(changes.ModifiedIDs)
	changes.Added = len(changes.AddedIDs)
	changes.Removed = len(changes.RemovedIDs)
	changes.Modified = len(changes.ModifiedIDs)
	return changes
}

func diffServer(before, after Server) ImportServerChange {
	fields := make([]string, 0)
	add := func(changed bool, label string) {
		if changed {
			fields = append(fields, label)
		}
	}
	add(before.Kind != after.Kind, "类型")
	add(before.Host != after.Host, "主机")
	add(before.Port != after.Port, "端口")
	add(before.Transport != after.Transport, "传输协议")
	add(before.TLSServerName != after.TLSServerName, "TLS 服务器名")
	add(before.TrustedCAPath != after.TrustedCAPath, "TLS CA 路径")
	add(before.CredentialRef != after.CredentialRef, "凭据引用")
	add(before.ServerID != after.ServerID, "服务器 ID")
	add(before.PublicHTTPPort != after.PublicHTTPPort, "HTTP 公网端口")
	add(before.PublicHTTPSPort != after.PublicHTTPSPort, "HTTPS 公网端口")
	add(before.PublicTCPMuxPort != after.PublicTCPMuxPort, "TCPMUX 公网端口")
	add(before.SubdomainHost != after.SubdomainHost, "子域名后缀")
	add(!reflect.DeepEqual(before.TCPMux, after.TCPMux), "TCPMux")
	add(!reflect.DeepEqual(before.DisableCustomTLSFirstByte, after.DisableCustomTLSFirstByte), "TLS 首字节兼容")
	return ImportServerChange{Changed: len(fields) != 0, Fields: fields}
}

func addedRules(rules []Rule) ImportChangeSet {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ImportChangeSet{Added: len(ids), AddedIDs: ids}
}

func addedVisitors(visitors []Visitor) ImportChangeSet {
	ids := make([]string, 0, len(visitors))
	for _, visitor := range visitors {
		ids = append(ids, visitor.ID)
	}
	sort.Strings(ids)
	return ImportChangeSet{Added: len(ids), AddedIDs: ids}
}
