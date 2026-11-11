package coreupdate

import (
	"fmt"
	"strconv"
	"strings"
)

type parsedVersion struct {
	core [3]int
	pre  []string
}

// CompareVersions compares two semantic versions. A leading "v" and build
// metadata are accepted; prerelease identifiers follow semantic-version
// ordering. The function returns -1, 0, or 1.
func CompareVersions(a, b string) (int, error) {
	av, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range av.core {
		if av.core[i] < bv.core[i] {
			return -1, nil
		}
		if av.core[i] > bv.core[i] {
			return 1, nil
		}
	}
	if len(av.pre) == 0 && len(bv.pre) == 0 {
		return 0, nil
	}
	if len(av.pre) == 0 {
		return 1, nil
	}
	if len(bv.pre) == 0 {
		return -1, nil
	}
	for i := 0; i < len(av.pre) && i < len(bv.pre); i++ {
		cmp := comparePrerelease(av.pre[i], bv.pre[i])
		if cmp != 0 {
			return cmp, nil
		}
	}
	if len(av.pre) < len(bv.pre) {
		return -1, nil
	}
	if len(av.pre) > len(bv.pre) {
		return 1, nil
	}
	return 0, nil
}

// IsPrerelease reports whether a version carries a prerelease identifier, for
// example v0.7.0-beta.1. Callers use it to keep beta builds out of release
// gates.
func IsPrerelease(raw string) (bool, error) {
	parsed, err := parseVersion(raw)
	if err != nil {
		return false, err
	}
	return len(parsed.pre) > 0, nil
}

func parseVersion(raw string) (parsedVersion, error) {
	var out parsedVersion
	if raw == "" || raw != strings.TrimSpace(raw) {
		return out, fmt.Errorf("%w: version is empty or contains whitespace", ErrInvalidManifest)
	}
	s := raw
	if strings.HasPrefix(s, "v") {
		s = s[1:]
	}
	if s == "" {
		return out, fmt.Errorf("%w: version is empty", ErrInvalidManifest)
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		build := s[i+1:]
		s = s[:i]
		if build == "" || !validIdentifierList(build, false) {
			return out, fmt.Errorf("%w: invalid build metadata", ErrInvalidManifest)
		}
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		s = s[:i]
		if pre == "" {
			return out, fmt.Errorf("%w: empty prerelease", ErrInvalidManifest)
		}
		out.pre = strings.Split(pre, ".")
		for _, id := range out.pre {
			if !validIdentifier(id, true) {
				return out, fmt.Errorf("%w: invalid prerelease identifier", ErrInvalidManifest)
			}
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("%w: version must contain major.minor.patch", ErrInvalidManifest)
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return out, fmt.Errorf("%w: invalid numeric version component", ErrInvalidManifest)
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return out, fmt.Errorf("%w: invalid numeric version component", ErrInvalidManifest)
		}
		out.core[i] = n
	}
	return out, nil
}

func validIdentifierList(raw string, prerelease bool) bool {
	parts := strings.Split(raw, ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !validIdentifier(part, prerelease) {
			return false
		}
	}
	return true
}

func validIdentifier(raw string, prerelease bool) bool {
	if raw == "" {
		return false
	}
	for _, r := range raw {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' {
			continue
		}
		return false
	}
	if prerelease && len(raw) > 1 && raw[0] == '0' {
		allDigits := true
		for _, r := range raw {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return false
		}
	}
	return true
}

func comparePrerelease(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		if an < bn {
			return -1
		}
		if an > bn {
			return 1
		}
		return 0
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	default:
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
}
