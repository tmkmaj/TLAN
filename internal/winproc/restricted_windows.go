//go:build windows

package winproc

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	createRestrictedDisableMaxPrivilege = 0x00000001
	createRestrictedLUA                 = 0x00000004
	saferScopeUser                      = 2
	saferLevelNormalUser                = 0x20000
	integrityUntrustedRID               = 0x0000
	integrityLowRID                     = 0x1000
	integrityMediumRID                  = 0x2000
	integrityHighRID                    = 0x3000
	integritySystemRID                  = 0x4000
)

var (
	advapi32                   = syscall.NewLazyDLL("advapi32.dll")
	procCreateRestrictedToken  = advapi32.NewProc("CreateRestrictedToken")
	procLookupPrivilegeName    = advapi32.NewProc("LookupPrivilegeNameW")
	procSaferCreateLevel       = advapi32.NewProc("SaferCreateLevel")
	procSaferComputeToken      = advapi32.NewProc("SaferComputeTokenFromLevel")
	procSaferCloseLevel        = advapi32.NewProc("SaferCloseLevel")
	launchRestrictedSerialized sync.Mutex
)

// LaunchOptions describes a suspended process launch with an already prepared
// STARTUPINFOEX handle list supplied by the caller.
type LaunchOptions struct {
	ApplicationName  string
	CommandLine      string
	CurrentDirectory string
	Environment      *uint16
	StartupInfo      *windows.StartupInfoEx
	CreationFlags    uint32
	InheritHandles   bool
}

// LaunchedProcess owns the returned process and thread handles. The process is
// still suspended; the caller must assign it to its job object before resuming.
type LaunchedProcess struct {
	windows.ProcessInformation
	Evidence Evidence
}

type tokenSnapshot struct {
	userSID               *windows.SID
	userSIDString         string
	sessionID             uint32
	logonSession          string
	integrityRID          uint32
	integrityLevel        string
	tokenType             uint32
	hasRestrictedSIDs     bool
	elevated              bool
	adminGroup            string
	enabledPrivileges     uint32
	enabledPrivilegeNames []string
	groupSIDs             []string
}

type privilegeChange struct {
	name     string
	previous windows.Tokenprivileges
}

type privilegeSet struct {
	token       windows.Token
	changes     []privilegeChange
	unavailable []string
}

type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// LaunchRestricted creates a process using a restricted lower-integrity token
// for the same user. It prefers the normal UAC linked token and falls back to a restricted
// version of the current token. The child remains suspended until the caller
// verifies and resumes it.
func LaunchRestricted(opts LaunchOptions) (*LaunchedProcess, error) {
	launchRestrictedSerialized.Lock()
	defer launchRestrictedSerialized.Unlock()

	if opts.ApplicationName == "" {
		return nil, fmt.Errorf("winproc: application name is required")
	}
	if !filepath.IsAbs(opts.ApplicationName) {
		return nil, fmt.Errorf("winproc: application path must be absolute: %q", opts.ApplicationName)
	}
	if opts.CommandLine == "" {
		return nil, fmt.Errorf("winproc: command line is required")
	}
	if opts.StartupInfo == nil {
		return nil, fmt.Errorf("winproc: STARTUPINFOEX is required")
	}
	if opts.CreationFlags&windows.CREATE_SUSPENDED == 0 {
		return nil, fmt.Errorf("winproc: CREATE_SUSPENDED is required for token verification")
	}
	if opts.CreationFlags&windows.EXTENDED_STARTUPINFO_PRESENT == 0 {
		return nil, fmt.Errorf("winproc: EXTENDED_STARTUPINFO_PRESENT is required for the restricted handle list")
	}

	parentToken, err := openCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("winproc: open current process token: %w", err)
	}
	defer parentToken.Close()
	parent, err := snapshotToken(parentToken)
	if err != nil {
		return nil, fmt.Errorf("winproc: inspect current process token: %w", err)
	}
	if err = validateParentSnapshot(parent); err != nil {
		return nil, err
	}
	targetRID, err := targetIntegrityRID(parent.integrityRID)
	if err != nil {
		return nil, err
	}

	childToken, tokenSource, err := selectRestrictedToken(parentToken, parent, targetRID)
	if err != nil {
		return nil, err
	}
	defer childToken.Close()
	preLaunch, err := snapshotToken(childToken)
	if err != nil {
		return nil, fmt.Errorf("winproc: inspect %s token before launch: %w", tokenSource, err)
	}
	if err = validateChildSnapshot(parent, preLaunch, targetRID, tokenSource+" token"); err != nil {
		return nil, err
	}

	privileges, err := enableLaunchPrivileges(parentToken)
	if err != nil {
		return nil, fmt.Errorf("winproc: prepare process-launch privileges: %w", err)
	}

	appName, err := windows.UTF16PtrFromString(opts.ApplicationName)
	if err != nil {
		_ = privileges.restore()
		return nil, fmt.Errorf("winproc: encode application path: %w", err)
	}
	commandLine, err := windows.UTF16PtrFromString(opts.CommandLine)
	if err != nil {
		_ = privileges.restore()
		return nil, fmt.Errorf("winproc: encode command line: %w", err)
	}
	var currentDirectory *uint16
	if opts.CurrentDirectory != "" {
		currentDirectory, err = windows.UTF16PtrFromString(opts.CurrentDirectory)
		if err != nil {
			_ = privileges.restore()
			return nil, fmt.Errorf("winproc: encode current directory: %w", err)
		}
	}

	startup := opts.StartupInfo
	if startup.StartupInfo.Cb == 0 {
		startup.StartupInfo.Cb = uint32(unsafe.Sizeof(*startup))
	}
	var proc windows.ProcessInformation
	createErr := windows.CreateProcessAsUser(
		childToken,
		appName,
		commandLine,
		nil,
		nil,
		opts.InheritHandles,
		opts.CreationFlags,
		opts.Environment,
		currentDirectory,
		(*windows.StartupInfo)(unsafe.Pointer(startup)),
		&proc,
	)
	restoreErr := privileges.restore()
	if createErr != nil {
		return nil, fmt.Errorf(
			"winproc: CreateProcessAsUserW with %s token failed (enabled:%v unavailable:%v): %w",
			tokenSource, privilegeNames(privileges.changes), privileges.unavailable, createErr,
		)
	}
	if restoreErr != nil {
		terminateUnresumedProcess(&proc)
		return nil, fmt.Errorf("winproc: restore parent process launch privileges after creating child: %w", restoreErr)
	}

	processToken, err := openProcessToken(proc.Process)
	if err != nil {
		terminateUnresumedProcess(&proc)
		return nil, fmt.Errorf("winproc: open suspended child process token: %w", err)
	}
	child, inspectErr := snapshotToken(processToken)
	_ = processToken.Close()
	if inspectErr != nil {
		terminateUnresumedProcess(&proc)
		return nil, fmt.Errorf("winproc: inspect suspended child process token: %w", inspectErr)
	}
	if err = validateChildSnapshot(parent, child, targetRID, "child process token"); err != nil {
		terminateUnresumedProcess(&proc)
		return nil, err
	}

	return &LaunchedProcess{
		ProcessInformation: proc,
		Evidence: Evidence{
			SchemaVersion:           EvidenceSchemaVersion,
			TokenSource:             tokenSource,
			UserSID:                 child.userSIDString,
			SessionID:               child.sessionID,
			LogonSession:            child.logonSession,
			ParentUserSID:           parent.userSIDString,
			ParentSessionID:         parent.sessionID,
			ParentLogonSession:      parent.logonSession,
			ParentIntegrityRID:      parent.integrityRID,
			ParentIntegrityLevel:    parent.integrityLevel,
			ParentEnabledPrivileges: parent.enabledPrivileges,
			IntegrityRID:            child.integrityRID,
			IntegrityLevel:          child.integrityLevel,
			TokenType:               child.tokenType,
			HasRestrictedSIDs:       child.hasRestrictedSIDs,
			TokenElevationFlag:      child.elevated,
			AdminGroup:              child.adminGroup,
			EnabledPrivilegeCount:   child.enabledPrivileges,
			EnabledPrivileges:       append([]string(nil), child.enabledPrivilegeNames...),
			GroupSIDs:               append([]string(nil), child.groupSIDs...),
		},
	}, nil
}

func selectRestrictedToken(parentToken windows.Token, parent tokenSnapshot, targetRID uint32) (windows.Token, string, error) {
	if linked, err := parentToken.GetLinkedToken(); err == nil {
		writable, duplicateErr := duplicateToken(linked)
		_ = linked.Close()
		if duplicateErr == nil {
			if integrityErr := setTokenIntegrity(writable, targetRID); integrityErr == nil {
				snapshot, inspectErr := snapshotToken(writable)
				if inspectErr == nil && validateChildSnapshot(parent, snapshot, targetRID, "uac-linked token") == nil {
					return writable, "uac-linked", nil
				}
			}
			_ = writable.Close()
		}
	}

	if safer, saferErr := createSaferNormalUserToken(parentToken); saferErr == nil {
		writable, duplicateErr := duplicateToken(safer)
		_ = safer.Close()
		if duplicateErr == nil {
			if integrityErr := setTokenIntegrity(writable, targetRID); integrityErr == nil {
				snapshot, inspectErr := snapshotToken(writable)
				if inspectErr == nil && validateChildSnapshot(parent, snapshot, targetRID, "safer-normal-user token") == nil {
					return writable, "safer-normal-user", nil
				}
			}
			_ = writable.Close()
		}
	}

	created, err := createRestrictedToken(parentToken)
	if err != nil {
		return 0, "", fmt.Errorf("winproc: no usable UAC linked or SAFER normal-user token and CreateRestrictedToken failed: %w", err)
	}
	writable, err := duplicateToken(created)
	_ = created.Close()
	if err != nil {
		return 0, "", fmt.Errorf("winproc: open created restricted token for integrity adjustment: %w", err)
	}
	if err = setTokenIntegrity(writable, targetRID); err != nil {
		_ = writable.Close()
		return 0, "", fmt.Errorf("winproc: set created token integrity to %s: %w", integrityLevelName(targetRID), err)
	}
	return writable, "created-restricted", nil
}

func duplicateToken(token windows.Token) (windows.Token, error) {
	var duplicate windows.Token
	if err := windows.DuplicateTokenEx(
		token,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&duplicate,
	); err != nil {
		return 0, err
	}
	return duplicate, nil
}

func openCurrentProcessToken() (windows.Token, error) {
	var token windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_PRIVILEGES)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &token); err != nil {
		return 0, err
	}
	return token, nil
}

// createSaferNormalUserToken asks SAFER for a normal-user token. The caller
// still verifies the Administrators group, integrity, and privileges.
func createSaferNormalUserToken(existing windows.Token) (windows.Token, error) {
	var level uintptr
	result, _, callErr := procSaferCreateLevel.Call(
		uintptr(saferScopeUser),
		uintptr(saferLevelNormalUser),
		0,
		uintptr(unsafe.Pointer(&level)),
		0,
	)
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}
	defer procSaferCloseLevel.Call(level)
	var token windows.Token
	result, _, callErr = procSaferComputeToken.Call(
		level,
		uintptr(existing),
		uintptr(unsafe.Pointer(&token)),
		0,
		0,
	)
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}
	return token, nil
}

// createRestrictedToken creates a limited-user token. LUA_TOKEN converts the
// Administrators group to deny-only and DISABLE_MAX_PRIVILEGE removes
// administrative privileges; both properties are verified from the token.
func createRestrictedToken(existing windows.Token) (windows.Token, error) {
	var restricted windows.Token
	result, _, callErr := procCreateRestrictedToken.Call(
		uintptr(existing),
		uintptr(createRestrictedDisableMaxPrivilege|createRestrictedLUA),
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, syscall.EINVAL
	}
	return restricted, nil
}

func setTokenIntegrity(token windows.Token, rid uint32) error {
	sid, err := windows.StringToSid(fmt.Sprintf("S-1-16-%d", rid))
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	return windows.SetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)),
		label.Size(),
	)
}

func targetIntegrityRID(parentRID uint32) (uint32, error) {
	switch {
	case parentRID >= integrityMediumRID:
		return integrityMediumRID, nil
	case parentRID == integrityLowRID || parentRID == integrityUntrustedRID:
		return parentRID, nil
	default:
		return 0, fmt.Errorf("winproc: unsupported parent integrity RID %#x; refusing to guess a child integrity level", parentRID)
	}
}

func validateParentSnapshot(parent tokenSnapshot) error {
	for _, forbidden := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20"} {
		if parent.userSIDString == forbidden {
			return fmt.Errorf("winproc: refusing to launch a managed worker from non-user token %s", parent.userSIDString)
		}
	}
	if parent.tokenType != windows.TokenPrimary {
		return fmt.Errorf("winproc: current process token is not a primary token")
	}
	var processSession uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &processSession); err != nil {
		return fmt.Errorf("winproc: read current process session: %w", err)
	}
	if parent.sessionID != processSession {
		return fmt.Errorf("winproc: token session %d differs from process session %d", parent.sessionID, processSession)
	}
	return nil
}

func validateChildSnapshot(parent, child tokenSnapshot, targetRID uint32, source string) error {
	if !sameSID(parent.userSID, child.userSID) {
		return fmt.Errorf("winproc: %s user %s differs from current user %s", source, child.userSIDString, parent.userSIDString)
	}
	if child.sessionID != parent.sessionID {
		return fmt.Errorf("winproc: %s session %d crosses current-user session %d", source, child.sessionID, parent.sessionID)
	}
	if child.logonSession != parent.logonSession {
		return fmt.Errorf("winproc: %s logon session %s differs from current logon session %s", source, child.logonSession, parent.logonSession)
	}
	if child.tokenType != windows.TokenPrimary {
		return fmt.Errorf("winproc: %s is not a primary token", source)
	}
	if child.integrityRID != targetRID {
		return fmt.Errorf("winproc: %s integrity is %s (%#x), expected %s (%#x)", source, child.integrityLevel, child.integrityRID, integrityLevelName(targetRID), targetRID)
	}
	if child.integrityRID > integrityMediumRID {
		return fmt.Errorf("winproc: %s retained elevated integrity %s", source, child.integrityLevel)
	}
	// TokenElevation can remain true for SAFER limited-user tokens. The
	// authoritative restrictions are the disabled Administrators group,
	// Medium/Low integrity, and the absence of non-allowlisted privileges.
	if child.elevated && child.adminGroup != "disabled" && child.adminGroup != "absent" {
		return fmt.Errorf("winproc: %s reports an elevated token with an active Administrators group", source)
	}
	if child.adminGroup == "enabled" {
		return fmt.Errorf("winproc: %s still has the Administrators group enabled", source)
	}
	for _, privilege := range child.enabledPrivilegeNames {
		if privilege != "SeChangeNotifyPrivilege" {
			return fmt.Errorf("winproc: %s still has non-allowlisted privilege %s", source, privilege)
		}
	}
	return nil
}

func snapshotToken(token windows.Token) (tokenSnapshot, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("read token user: %w", err)
	}
	if user.User.Sid == nil {
		return tokenSnapshot{}, fmt.Errorf("token user SID is missing")
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("copy token user SID: %w", err)
	}
	userString := userSID.String()
	if userString == "" {
		return tokenSnapshot{}, fmt.Errorf("convert token user SID to string")
	}
	sessionID, err := queryTokenUint32(token, windows.TokenSessionId)
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("read token session: %w", err)
	}
	stats, err := queryTokenStatistics(token)
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("read token statistics: %w", err)
	}
	restricted, err := queryTokenUint32(token, windows.TokenHasRestrictions)
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("read token restrictions: %w", err)
	}
	elevated, err := queryTokenUint32(token, windows.TokenElevation)
	if err != nil {
		return tokenSnapshot{}, fmt.Errorf("read token elevation: %w", err)
	}
	integrityRID, integrityLevel, err := queryTokenIntegrity(token)
	if err != nil {
		return tokenSnapshot{}, err
	}
	groups, adminGroup, err := queryTokenGroups(token)
	if err != nil {
		return tokenSnapshot{}, err
	}
	enabledPrivilegeNames, err := queryEnabledPrivileges(token)
	if err != nil {
		return tokenSnapshot{}, err
	}
	return tokenSnapshot{
		userSID:               userSID,
		userSIDString:         userString,
		sessionID:             sessionID,
		logonSession:          luidString(stats.AuthenticationID),
		integrityRID:          integrityRID,
		integrityLevel:        integrityLevel,
		tokenType:             stats.TokenType,
		hasRestrictedSIDs:     restricted != 0,
		elevated:              elevated != 0,
		adminGroup:            adminGroup,
		enabledPrivileges:     uint32(len(enabledPrivilegeNames)),
		enabledPrivilegeNames: enabledPrivilegeNames,
		groupSIDs:             groups,
	}, nil
}

func queryTokenUint32(token windows.Token, class uint32) (uint32, error) {
	var value uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		token,
		class,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	); err != nil {
		return 0, err
	}
	if returned == 0 || returned > uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("unexpected token information size %d", returned)
	}
	return value, nil
}

func queryTokenStatistics(token windows.Token) (tokenStatistics, error) {
	var stats tokenStatistics
	var returned uint32
	if err := windows.GetTokenInformation(
		token,
		windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&stats)),
		uint32(unsafe.Sizeof(stats)),
		&returned,
	); err != nil {
		return tokenStatistics{}, err
	}
	if returned != uint32(unsafe.Sizeof(stats)) {
		return tokenStatistics{}, fmt.Errorf("unexpected token statistics size %d", returned)
	}
	return stats, nil
}

func queryTokenIntegrity(token windows.Token) (uint32, string, error) {
	var needed uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &needed)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return 0, "", fmt.Errorf("size token integrity: %w", err)
	}
	if needed == 0 {
		return 0, "", fmt.Errorf("token integrity buffer is empty")
	}
	buffer := make([]byte, needed)
	if err = windows.GetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		&buffer[0],
		uint32(len(buffer)),
		&needed,
	); err != nil {
		return 0, "", fmt.Errorf("read token integrity: %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil || label.Label.Sid.SubAuthorityCount() == 0 {
		return 0, "", fmt.Errorf("token integrity SID is missing")
	}
	rid := label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount() - 1))
	return rid, integrityLevelName(rid), nil
}

func queryTokenGroups(token windows.Token) ([]string, string, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, "", fmt.Errorf("read token groups: %w", err)
	}
	adminGroup := "absent"
	result := make([]string, 0, groups.GroupCount)
	for _, group := range groups.AllGroups() {
		if group.Sid == nil {
			return nil, "", fmt.Errorf("token contains a nil group SID")
		}
		sid := group.Sid.String()
		if sid == "" {
			return nil, "", fmt.Errorf("convert token group SID to string")
		}
		result = append(result, sid)
		if sid == "S-1-5-32-544" {
			switch {
			case group.Attributes&windows.SE_GROUP_ENABLED != 0:
				adminGroup = "enabled"
			case group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0:
				adminGroup = "disabled"
			default:
				adminGroup = "present-disabled"
			}
		}
	}
	sort.Strings(result)
	return result, adminGroup, nil
}

func queryEnabledPrivileges(token windows.Token) ([]string, error) {
	privileges, err := queryTokenPrivileges(token)
	if err != nil {
		return nil, err
	}
	var enabled []string
	for _, privilege := range privileges {
		if privilege.Attributes&(windows.SE_PRIVILEGE_ENABLED|windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0 {
			enabled = append(enabled, lookupPrivilegeName(privilege.Luid))
		}
	}
	sort.Strings(enabled)
	return enabled, nil
}

func queryTokenPrivileges(token windows.Token) ([]windows.LUIDAndAttributes, error) {
	var needed uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("size token privileges: %w", err)
	}
	if needed == 0 {
		return nil, nil
	}
	buffer := make([]byte, needed)
	if err = windows.GetTokenInformation(
		token,
		windows.TokenPrivileges,
		&buffer[0],
		uint32(len(buffer)),
		&needed,
	); err != nil {
		return nil, fmt.Errorf("read token privileges: %w", err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	return append([]windows.LUIDAndAttributes(nil), privileges.AllPrivileges()...), nil
}

func lookupPrivilegeName(luid windows.LUID) string {
	name := make([]uint16, 256)
	size := uint32(len(name))
	result, _, _ := procLookupPrivilegeName.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 {
		return "LUID-" + luidString(luid)
	}
	return windows.UTF16ToString(name[:size])
}

func enableLaunchPrivileges(token windows.Token) (*privilegeSet, error) {
	set := &privilegeSet{token: token}
	for _, name := range []string{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"} {
		change, available, err := enablePrivilege(token, name)
		if err != nil {
			_ = set.restore()
			return nil, fmt.Errorf("enable %s: %w", name, err)
		}
		if available {
			set.changes = append(set.changes, change)
		} else {
			set.unavailable = append(set.unavailable, name)
		}
	}
	return set, nil
}

func enablePrivilege(token windows.Token, name string) (privilegeChange, bool, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return privilegeChange{}, false, err
	}
	var luid windows.LUID
	if err = windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return privilegeChange{}, false, err
	}
	privileges, err := queryTokenPrivileges(token)
	if err != nil {
		return privilegeChange{}, false, err
	}
	var previousState windows.LUIDAndAttributes
	found := false
	for _, privilege := range privileges {
		if privilege.Luid == luid {
			previousState = privilege
			found = true
			break
		}
	}
	if !found {
		return privilegeChange{}, false, nil
	}
	previous := windows.Tokenprivileges{PrivilegeCount: 1}
	previous.AllPrivileges()[0] = previousState
	requested := windows.Tokenprivileges{PrivilegeCount: 1}
	requested.AllPrivileges()[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: previousState.Attributes | windows.SE_PRIVILEGE_ENABLED,
	}
	if err = windows.AdjustTokenPrivileges(
		token,
		false,
		&requested,
		uint32(unsafe.Sizeof(requested)),
		nil,
		nil,
	); err != nil {
		if err == windows.ERROR_NOT_ALL_ASSIGNED {
			return privilegeChange{}, false, nil
		}
		return privilegeChange{}, false, err
	}
	return privilegeChange{name: name, previous: previous}, true, nil
}

func (set *privilegeSet) restore() error {
	var firstErr error
	for index := len(set.changes) - 1; index >= 0; index-- {
		change := set.changes[index]
		if err := windows.AdjustTokenPrivileges(
			set.token,
			false,
			&change.previous,
			uint32(unsafe.Sizeof(change.previous)),
			nil,
			nil,
		); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore %s: %w", change.name, err)
		}
	}
	return firstErr
}

func privilegeNames(changes []privilegeChange) []string {
	names := make([]string, 0, len(changes))
	for _, change := range changes {
		names = append(names, change.name)
	}
	return names
}

func openProcessToken(process windows.Handle) (windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return 0, err
	}
	return token, nil
}

func terminateUnresumedProcess(proc *windows.ProcessInformation) {
	if proc.Process != 0 {
		_ = windows.TerminateProcess(proc.Process, 1)
		_, _ = windows.WaitForSingleObject(proc.Process, 3000)
	}
	if proc.Thread != 0 {
		_ = windows.CloseHandle(proc.Thread)
		proc.Thread = 0
	}
	if proc.Process != 0 {
		_ = windows.CloseHandle(proc.Process)
		proc.Process = 0
	}
}

func integrityLevelName(rid uint32) string {
	switch rid {
	case integrityUntrustedRID:
		return "Untrusted"
	case integrityLowRID:
		return "Low"
	case integrityMediumRID:
		return "Medium"
	case integrityHighRID:
		return "High"
	case integritySystemRID:
		return "System"
	default:
		return fmt.Sprintf("RID-%#x", rid)
	}
}

func sameSID(left, right *windows.SID) bool {
	return left != nil && right != nil && left.Equals(right)
}

func luidString(luid windows.LUID) string {
	return fmt.Sprintf("%08x:%08x", uint32(luid.HighPart), luid.LowPart)
}
