package egress

import (
	"errors"
	"strings"
	"testing"
)

func validRule() AppRule {
	return AppRule{
		ID:              "browser",
		Name:            "Browser",
		ExePath:         `C:\Program Files\Example\browser.exe`,
		IncludeChildren: true,
		Enabled:         true,
		Protocols:       []Protocol{ProtocolTCP, ProtocolUDP},
	}
}

func validProfile() EgressProfile {
	return EgressProfile{
		ID:      "work",
		Name:    "Work",
		Version: 1,
		Server: EgressServer{
			Endpoint:      "egress.example.com",
			Port:          443,
			ServerName:    "egress.example.com",
			TrustedCARef:  "gateway-ca",
			CredentialRef: "gateway-credential",
		},
		Policy: EgressPolicy{
			IPv6Policy:        IPv6PolicyBlock,
			DNSPolicy:         DNSPolicyRemote,
			KillSwitch:        true,
			TargetAllowList:   []string{"example.com:443", "203.0.113.0/24"},
			killSwitchPresent: true,
		},
		Rules:        []AppRule{validRule()},
		DesiredState: DesiredRunning,
	}
}

func TestEgressStateTransitionTable(t *testing.T) {
	t.Parallel()

	validStates := []EgressState{
		StateStopped,
		StateStarting,
		StateRunning,
		StateDegraded,
		StateStopping,
		StateError,
		StateBlocked,
	}
	for _, state := range validStates {
		if !state.Valid() {
			t.Fatalf("state %q should be valid", state)
		}
	}
	if EgressState("unknown").Valid() {
		t.Fatal("unknown state should be invalid")
	}

	tests := []struct {
		name string
		from EgressState
		to   EgressState
		want bool
	}{
		{name: "stopped to starting", from: StateStopped, to: StateStarting, want: true},
		{name: "starting to running", from: StateStarting, to: StateRunning, want: true},
		{name: "starting to stopped is invalid", from: StateStarting, to: StateStopped},
		{name: "running to degraded", from: StateRunning, to: StateDegraded, want: true},
		{name: "running to error", from: StateRunning, to: StateError, want: true},
		{name: "running to starting is invalid", from: StateRunning, to: StateStarting},
		{name: "degraded to running", from: StateDegraded, to: StateRunning, want: true},
		{name: "stopping to stopped", from: StateStopping, to: StateStopped, want: true},
		{name: "error to starting", from: StateError, to: StateStarting, want: true},
		{name: "blocked to stopped", from: StateBlocked, to: StateStopped, want: true},
		{name: "stopped to running", from: StateStopped, to: StateRunning},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.from.CanTransitionTo(tc.to); got != tc.want {
				t.Fatalf("CanTransitionTo(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

func TestNormalizeExePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "canonical drive path", input: `C:\Program Files\Example\app.exe`, want: `C:\Program Files\Example\app.exe`},
		{name: "forward slashes", input: `C:/Program Files/Example/app.exe`, want: `C:\Program Files\Example\app.exe`},
		{name: "redundant separators", input: `C:\Program Files\\Example\app.exe`, want: `C:\Program Files\Example\app.exe`},
		{name: "empty", input: "", wantErr: true},
		{name: "relative", input: `Example\app.exe`, wantErr: true},
		{name: "drive relative", input: `C:Example\app.exe`, wantErr: true},
		{name: "UNC", input: `\\server\share\app.exe`, wantErr: true},
		{name: "device path", input: `\\?\C:\Example\app.exe`, wantErr: true},
		{name: "parent traversal", input: `C:\Example\..\app.exe`, wantErr: true},
		{name: "reserved device name", input: `C:\Example\CON.exe`, wantErr: true},
		{name: "trailing dot segment", input: `C:\Example.\app.exe`, wantErr: true},
		{name: "root is not executable path", input: `C:\`, wantErr: true},
		{name: "control character", input: "C:\\Example\\app\x00.exe", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeExePath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeExePath(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeExePath(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeExePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}

	key := ExePathKey(`C:\Program Files\Example\APP.EXE`)
	if key != strings.ToLower(`C:\Program Files\Example\APP.EXE`) {
		t.Fatalf("ExePathKey() = %q", key)
	}
}

func TestValidateProfileTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*EgressProfile)
		errIs  error
	}{
		{name: "valid"},
		{name: "empty id", mutate: func(p *EgressProfile) { p.ID = "" }, errIs: ErrInvalidProfile},
		{name: "empty name", mutate: func(p *EgressProfile) { p.Name = "" }, errIs: ErrInvalidProfile},
		{name: "invalid version", mutate: func(p *EgressProfile) { p.Version = 0 }, errIs: ErrInvalidProfile},
		{name: "missing endpoint", mutate: func(p *EgressProfile) { p.Server.Endpoint = "" }, errIs: ErrInvalidProfile},
		{name: "endpoint with scheme", mutate: func(p *EgressProfile) { p.Server.Endpoint = "https://example.com" }, errIs: ErrInvalidProfile},
		{name: "invalid port", mutate: func(p *EgressProfile) { p.Server.Port = 70000 }, errIs: ErrInvalidProfile},
		{name: "missing credential ref", mutate: func(p *EgressProfile) { p.Server.CredentialRef = "" }, errIs: ErrInvalidProfile},
		{name: "empty ipv6 policy", mutate: func(p *EgressProfile) { p.Policy.IPv6Policy = "" }, errIs: ErrInvalidProfile},
		{name: "unknown ipv6 policy", mutate: func(p *EgressProfile) { p.Policy.IPv6Policy = "allow" }, errIs: ErrInvalidProfile},
		{name: "empty dns policy", mutate: func(p *EgressProfile) { p.Policy.DNSPolicy = "" }, errIs: ErrInvalidProfile},
		{name: "unknown dns policy", mutate: func(p *EgressProfile) { p.Policy.DNSPolicy = "system" }, errIs: ErrInvalidProfile},
		{name: "no rules", mutate: func(p *EgressProfile) { p.Rules = nil }, errIs: ErrInvalidProfile},
		{name: "no enabled rules", mutate: func(p *EgressProfile) { p.Rules[0].Enabled = false }, errIs: ErrInvalidProfile},
		{name: "unknown desired state", mutate: func(p *EgressProfile) { p.DesiredState = "auto" }, errIs: ErrInvalidProfile},
		{name: "duplicate rule id", mutate: func(p *EgressProfile) {
			second := validRule()
			second.Name = "Second"
			second.ExePath = `C:\Example\second.exe`
			p.Rules = append(p.Rules, second)
		}, errIs: ErrInvalidProfile},
		{name: "duplicate rule name case insensitive", mutate: func(p *EgressProfile) {
			second := validRule()
			second.ID = "second"
			second.Name = "BROWSER"
			second.ExePath = `C:\Example\second.exe`
			p.Rules = append(p.Rules, second)
		}, errIs: ErrInvalidProfile},
		{name: "duplicate rule path case insensitive", mutate: func(p *EgressProfile) {
			second := validRule()
			second.ID = "second"
			second.Name = "Second"
			second.ExePath = `c:\program files\example\BROWSER.EXE`
			p.Rules = append(p.Rules, second)
		}, errIs: ErrInvalidProfile},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profile := validProfile()
			if tc.mutate != nil {
				tc.mutate(&profile)
			}
			err := ValidateProfile(profile)
			if tc.errIs == nil {
				if err != nil {
					t.Fatalf("ValidateProfile(): %v", err)
				}
				return
			}
			if !errors.Is(err, tc.errIs) {
				t.Fatalf("ValidateProfile() error = %v, want errors.Is(%v)", err, tc.errIs)
			}
		})
	}
}

func TestValidateRuleTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*AppRule)
		errIs  error
	}{
		{name: "valid"},
		{name: "empty id", mutate: func(r *AppRule) { r.ID = "" }, errIs: ErrInvalidRule},
		{name: "invalid id", mutate: func(r *AppRule) { r.ID = "../escape" }, errIs: ErrInvalidRule},
		{name: "empty name", mutate: func(r *AppRule) { r.Name = "" }, errIs: ErrInvalidRule},
		{name: "relative executable", mutate: func(r *AppRule) { r.ExePath = `app.exe` }, errIs: ErrInvalidRule},
		{name: "no protocols", mutate: func(r *AppRule) { r.Protocols = nil }, errIs: ErrInvalidRule},
		{name: "unsupported protocol", mutate: func(r *AppRule) { r.Protocols = []Protocol{"icmp"} }, errIs: ErrUnsupported},
		{name: "duplicate protocol", mutate: func(r *AppRule) { r.Protocols = []Protocol{ProtocolTCP, ProtocolTCP} }, errIs: ErrInvalidRule},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := validRule()
			if tc.mutate != nil {
				tc.mutate(&rule)
			}
			err := ValidateRule(rule)
			if tc.errIs == nil {
				if err != nil {
					t.Fatalf("ValidateRule(): %v", err)
				}
				return
			}
			if !errors.Is(err, tc.errIs) {
				t.Fatalf("ValidateRule() error = %v, want errors.Is(%v)", err, tc.errIs)
			}
		})
	}
}

func TestDecodeProfilesIsStrict(t *testing.T) {
	t.Parallel()

	valid := `{
  "schemaVersion": 1,
  "profiles": [{
    "id": "work",
    "name": "Work",
    "version": 1,
    "server": {"endpoint":"egress.example.com","port":443,"serverName":"egress.example.com","trustedCaRef":"gateway-ca","credentialRef":"gateway-credential"},
    "policy": {"ipv6Policy":"block","dnsPolicy":"remote","killSwitch":true,"targetAllowList":["example.com:443"]},
    "rules": [{"id":"browser","name":"Browser","exePath":"C:\\Program Files\\Example\\browser.exe","includeChildren":true,"enabled":true,"protocols":["tcp","udp"]}],
    "desiredState": "running"
  }]
}`
	if _, err := DecodeProfiles(strings.NewReader(valid)); err != nil {
		t.Fatalf("DecodeProfiles(valid): %v", err)
	}

	unknown := strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": 1, "unknown": true`, 1)
	if _, err := DecodeProfiles(strings.NewReader(unknown)); err == nil {
		t.Fatal("DecodeProfiles accepted an unknown field")
	}
	if _, err := DecodeProfiles(strings.NewReader(valid + `{}`)); err == nil {
		t.Fatal("DecodeProfiles accepted trailing JSON")
	}

	missingKillSwitch := strings.Replace(valid, `,"killSwitch":true`, ``, 1)
	if _, err := DecodeProfiles(strings.NewReader(missingKillSwitch)); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("missing killSwitch error = %v, want ErrInvalidProfile", err)
	}
}
