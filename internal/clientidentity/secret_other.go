//go:build !windows

package clientidentity

func ProtectSecret(value string) (string, error)         { return value, nil }
func UnprotectSecret(value string) (string, error)       { return value, nil }
func UnprotectSecretStrict(value string) (string, error) { return value, nil }
