//go:build windows

package clientidentity

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectSecret binds saved private material to the current Windows user.
func ProtectSecret(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	data := []byte(value)
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return "dpapi:" + base64.StdEncoding.EncodeToString(unsafe.Slice(out.Data, out.Size)), nil
}

// UnprotectSecretStrict rejects legacy plaintext values. Callers that store
// publish credentials or private keys must use this variant so a modified
// file cannot silently downgrade protection.
func UnprotectSecretStrict(value string) (string, error) {
	if !strings.HasPrefix(value, "dpapi:") {
		return "", fmt.Errorf("secret is not DPAPI protected")
	}
	return UnprotectSecret(value)
}

func UnprotectSecret(value string) (string, error) {
	if !strings.HasPrefix(value, "dpapi:") {
		return value, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "dpapi:"))
	if err != nil || len(data) == 0 {
		return "", fmtSecretError()
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}
