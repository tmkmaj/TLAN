//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"golang.org/x/sys/windows"
)

const (
	iphlpAFInet                = 2
	tcpTableOwnerPIDListener   = 5
	udpTableOwnerPID           = 1
	tcpStateListen             = 2
	maxLocalListeningRowsLimit = 20000
)

var (
	iphlpapiDLL           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTbl = iphlpapiDLL.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTbl = iphlpapiDLL.NewProc("GetExtendedUdpTable")
)

type localPortEntry struct {
	PID         uint32
	ProcessName string
	Protocol    string // "tcp" or "udp"
	BindIP      string
	TargetIP    string // sanitized for FRP: "127.0.0.1" when 0.0.0.0 or 127.x.x.x, otherwise BindIP
	Port        int
}

func listLocalListeningPorts() ([]localPortEntry, error) {
	names := snapshotProcessNames()
	tcpEntries, tcpErr := queryTCPListeners(names)
	udpEntries, udpErr := queryUDPListeners(names)
	if tcpErr != nil && udpErr != nil {
		return nil, fmt.Errorf(tr("枚举本机监听端口失败: %w", "failed to enumerate listening ports: %w"), tcpErr)
	}
	seen := make(map[string]struct{}, len(tcpEntries)+len(udpEntries))
	combined := make([]localPortEntry, 0, len(tcpEntries)+len(udpEntries))
	for _, list := range [][]localPortEntry{tcpEntries, udpEntries} {
		for _, entry := range list {
			key := fmt.Sprintf("%s|%s|%d|%d", entry.Protocol, entry.BindIP, entry.Port, entry.PID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			combined = append(combined, entry)
		}
	}
	sort.Slice(combined, func(i, j int) bool {
		if combined[i].Port != combined[j].Port {
			return combined[i].Port < combined[j].Port
		}
		if combined[i].Protocol != combined[j].Protocol {
			return combined[i].Protocol < combined[j].Protocol
		}
		if combined[i].ProcessName != combined[j].ProcessName {
			return strings.ToLower(combined[i].ProcessName) < strings.ToLower(combined[j].ProcessName)
		}
		return combined[i].PID < combined[j].PID
	})
	return combined, nil
}

func snapshotProcessNames() map[uint32]string {
	result := make(map[uint32]string)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return result
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return result
	}
	for {
		exe := windows.UTF16ToString(pe.ExeFile[:])
		if exe != "" {
			result[pe.ProcessID] = exe
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return result
}

func queryTCPListeners(names map[uint32]string) ([]localPortEntry, error) {
	buf, err := callIPHelperTable(procGetExtendedTcpTbl, tcpTableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[0:4]))
	if numEntries <= 0 || numEntries > maxLocalListeningRowsLimit {
		return nil, nil
	}
	const rowSize = 24 // MIB_TCPROW_OWNER_PID: 6 * DWORD
	out := make([]localPortEntry, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		state := binary.LittleEndian.Uint32(buf[off : off+4])
		if state != tcpStateListen {
			continue
		}
		localAddr := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		localPortRaw := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		port := decodeWinPort(localPortRaw)
		if port < 1 || port > 65535 {
			continue
		}
		pid := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		bindIP := ipv4FromDWORD(localAddr)
		out = append(out, makeLocalPortEntry(pid, names[pid], "tcp", bindIP, port))
	}
	return out, nil
}

func queryUDPListeners(names map[uint32]string) ([]localPortEntry, error) {
	buf, err := callIPHelperTable(procGetExtendedUdpTbl, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[0:4]))
	if numEntries <= 0 || numEntries > maxLocalListeningRowsLimit {
		return nil, nil
	}
	const rowSize = 12 // MIB_UDPROW_OWNER_PID: 3 * DWORD
	out := make([]localPortEntry, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		localAddr := binary.LittleEndian.Uint32(buf[off : off+4])
		localPortRaw := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		port := decodeWinPort(localPortRaw)
		if port < 1 || port > 65535 {
			continue
		}
		pid := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		bindIP := ipv4FromDWORD(localAddr)
		out = append(out, makeLocalPortEntry(pid, names[pid], "udp", bindIP, port))
	}
	return out, nil
}

func callIPHelperTable(proc *windows.LazyProc, tableClass uintptr) ([]byte, error) {
	size := uint32(16 * 1024)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		r1, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(iphlpAFInet),
			tableClass,
			0,
		)
		if r1 == 0 {
			return buf, nil
		}
		if r1 == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			if size < 64 {
				size = 64
			}
			continue
		}
		return nil, syscall.Errno(r1)
	}
	return nil, fmt.Errorf("iphlpapi table buffer overflow")
}

func makeLocalPortEntry(pid uint32, procName, protocol, bindIP string, port int) localPortEntry {
	procName = strings.TrimSpace(procName)
	if procName == "" {
		if pid == 0 {
			procName = "System Idle"
		} else if pid == 4 {
			procName = "System"
		} else {
			procName = fmt.Sprintf("PID %d", pid)
		}
	}
	_, targetIP, err := normalizeLocalTargetIP(bindIP)
	if err != nil {
		targetIP = "127.0.0.1"
	}
	return localPortEntry{
		PID:         pid,
		ProcessName: procName,
		Protocol:    protocol,
		BindIP:      bindIP,
		TargetIP:    targetIP,
		Port:        port,
	}
}

func decodeWinPort(networkOrder uint32) int {
	hi := byte(networkOrder & 0xFF)
	lo := byte((networkOrder >> 8) & 0xFF)
	return int(hi)<<8 | int(lo)
}

func ipv4FromDWORD(dw uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(dw), byte(dw>>8), byte(dw>>16), byte(dw>>24))
}

func normalizeLocalTargetIP(rawIP string) (string, string, error) {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" || strings.EqualFold(trimmed, "localhost") {
		return "loopback", "127.0.0.1", nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.Is4() {
		return "", "", fmt.Errorf(tr("本地 IP 必须是有效的 IPv4 地址（留空或填 127.0.0.1 表示本机）", "local IP must be a valid IPv4 address (leave blank or use 127.0.0.1)"))
	}
	if addr.IsUnspecified() || addr.IsLoopback() {
		return "loopback", "127.0.0.1", nil
	}
	if !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
		return "", "", fmt.Errorf(tr("本地/内网目标 IP 仅支持 127.0.0.1 或局域网私有 IPv4（如 192.168.x.x / 10.x.x.x）", "target IP must be 127.0.0.1 or a private LAN IPv4 address"))
	}
	return "lan", addr.String(), nil
}

func filterLocalPortEntries(entries []localPortEntry, query, protoFilter string) []localPortEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	proto := strings.ToLower(strings.TrimSpace(protoFilter))
	if proto == "all" || proto == "全部" {
		proto = ""
	}
	out := make([]localPortEntry, 0, len(entries))
	for _, entry := range entries {
		if proto != "" && entry.Protocol != proto {
			continue
		}
		if q != "" {
			matches := strings.Contains(strings.ToLower(entry.ProcessName), q) ||
				strings.Contains(strconv.Itoa(entry.Port), q) ||
				strings.Contains(strconv.FormatUint(uint64(entry.PID), 10), q) ||
				strings.Contains(entry.BindIP, q) ||
				strings.Contains(entry.TargetIP, q)
			if !matches {
				continue
			}
		}
		out = append(out, entry)
	}
	return out
}

func suggestRuleName(processName string, localPort int, existing []frpctl.Rule) string {
	base := strings.TrimSpace(processName)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	var cleaned strings.Builder
	for _, r := range base {
		if r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r > 127 {
			cleaned.WriteRune(r)
		}
	}
	label := strings.Trim(cleaned.String(), "._-")
	if label == "" {
		label = fmt.Sprintf("服务_%d", localPort)
	} else {
		label = fmt.Sprintf("%s_%d", label, localPort)
	}
	used := make(map[string]struct{}, len(existing))
	for _, rule := range existing {
		used[strings.ToLower(strings.TrimSpace(rule.Name))] = struct{}{}
	}
	if _, conflict := used[strings.ToLower(label)]; !conflict {
		return truncateRunes(label, 48)
	}
	for n := 2; n < 1000; n++ {
		candidate := fmt.Sprintf("%s_%d", truncateRunes(label, 40), n)
		if _, conflict := used[strings.ToLower(candidate)]; !conflict {
			return candidate
		}
	}
	return truncateRunes(label, 48)
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

const (
	defaultFRPPortMin = 60000
	defaultFRPPortMax = 61000
)

func suggestRemotePort(existing []frpctl.Rule, localPort int) int {
	return suggestRemotePortInRange(existing, localPort, defaultFRPPortMin, defaultFRPPortMax)
}

func suggestRemotePortInRange(existing []frpctl.Rule, localPort, minPort, maxPort int) int {
	if minPort < 1 || maxPort > 65535 || minPort > maxPort {
		minPort, maxPort = defaultFRPPortMin, defaultFRPPortMax
	}
	used := make(map[int]struct{}, len(existing))
	for _, rule := range existing {
		if rule.Exposure.RemotePort > 0 {
			used[rule.Exposure.RemotePort] = struct{}{}
		}
	}
	if localPort >= minPort && localPort <= maxPort {
		if _, conflict := used[localPort]; !conflict {
			return localPort
		}
	}
	for port := minPort; port <= maxPort; port++ {
		if _, conflict := used[port]; !conflict {
			return port
		}
	}
	return minPort
}

func buildQuickFRPRules(existing []frpctl.Rule, name, localIP string, localPort, remotePort int, protoChoice string) ([]frpctl.Rule, error) {
	if localPort < 1 || localPort > 65535 {
		return nil, fmt.Errorf(tr("本地端口必须在 1 到 65535 之间", "local port must be between 1 and 65535"))
	}
	if remotePort < 1 || remotePort > 65535 {
		return nil, fmt.Errorf(tr("服务器映射端口必须在 1 到 65535 之间", "server port must be between 1 and 65535"))
	}
	targetKind, targetHost, err := normalizeLocalTargetIP(localIP)
	if err != nil {
		return nil, err
	}
	var protocols []string
	switch strings.ToLower(strings.TrimSpace(protoChoice)) {
	case "", "tcp":
		protocols = []string{"tcp"}
	case "udp":
		protocols = []string{"udp"}
	case "tcp+udp", "tcp + udp", "both":
		protocols = []string{"tcp", "udp"}
	default:
		return nil, fmt.Errorf(tr("不支持的映射协议 %q，请选择 TCP、UDP 或 TCP+UDP", "unsupported protocol %q; choose TCP, UDP, or TCP+UDP"), protoChoice)
	}
	if len(existing)+len(protocols) > frpctl.MaxRules {
		return nil, fmt.Errorf(tr("当前配置最多支持 %d 条端口映射规则", "maximum %d rules supported per profile"), frpctl.MaxRules)
	}

	usedNames := make(map[string]struct{}, len(existing))
	usedPorts := make(map[string]struct{}, len(existing))
	for _, rule := range existing {
		usedNames[strings.ToLower(strings.TrimSpace(rule.Name))] = struct{}{}
		if rule.Type == "tcp" || rule.Type == "udp" {
			usedPorts[fmt.Sprintf("%s:%d", rule.Type, rule.Exposure.RemotePort)] = struct{}{}
		}
	}

	baseName := strings.TrimSpace(name)
	if baseName == "" {
		baseName = fmt.Sprintf(tr("映射_%d", "map_%d"), localPort)
	}

	created := make([]frpctl.Rule, 0, len(protocols))
	for _, proto := range protocols {
		portKey := fmt.Sprintf("%s:%d", proto, remotePort)
		if _, conflict := usedPorts[portKey]; conflict {
			return nil, fmt.Errorf(tr("服务器 %s 端口 %d 已被现有规则占用，请换一个端口", "server %s port %d is already used by another rule"), strings.ToUpper(proto), remotePort)
		}
		usedPorts[portKey] = struct{}{}

		ruleName := baseName
		if len(protocols) > 1 {
			ruleName = fmt.Sprintf("%s_%s", truncateRunes(baseName, 44), strings.ToUpper(proto))
		}
		if _, conflict := usedNames[strings.ToLower(ruleName)]; conflict {
			for n := 2; n < 1000; n++ {
				cand := fmt.Sprintf("%s_%d", truncateRunes(ruleName, 40), n)
				if _, exists := usedNames[strings.ToLower(cand)]; !exists {
					ruleName = cand
					break
				}
			}
		}
		usedNames[strings.ToLower(ruleName)] = struct{}{}

		id, idErr := frpctl.NewRuleID()
		if idErr != nil {
			return nil, idErr
		}
		created = append(created, frpctl.Rule{
			ID:      id,
			Name:    ruleName,
			Type:    proto,
			Enabled: true,
			Target: frpctl.Target{
				Kind: targetKind,
				Host: targetHost,
				Port: localPort,
			},
			Exposure: frpctl.Exposure{
				RemotePort: remotePort,
			},
		})
	}
	return created, nil
}
