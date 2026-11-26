//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/lxn/walk"
	"golang.org/x/sys/windows"
)

const (
	langAuto = "auto"
	langZH   = "zh"
	langEN   = "en"
)

var activeLangCode atomic.Int32 // 0 = zh, 1 = en

var (
	kernel32DLL                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetUserDefaultUILang    = kernel32DLL.NewProc("GetUserDefaultUILanguage")
)

func init() {
	setActiveLanguage(resolveLanguage(langAuto))
}

func normalizeLanguage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case langZH, "zh-cn", "zh_cn", "chinese":
		return langZH
	case langEN, "en-us", "en_us", "english":
		return langEN
	default:
		return langAuto
	}
}

func languageIndex(value string) int {
	switch normalizeLanguage(value) {
	case langZH:
		return 1
	case langEN:
		return 2
	default:
		return 0
	}
}

func languageFromIndex(index int) string {
	switch index {
	case 1:
		return langZH
	case 2:
		return langEN
	default:
		return langAuto
	}
}

func systemPrefersEnglish() bool {
	if procGetUserDefaultUILang.Find() != nil {
		return false
	}
	langID, _, _ := procGetUserDefaultUILang.Call()
	primary := uint16(langID) & 0x03ff
	// 0x04 = LANG_CHINESE
	return primary != 0x04
}

func resolveLanguage(value string) string {
	switch normalizeLanguage(value) {
	case langZH:
		return langZH
	case langEN:
		return langEN
	default:
		if systemPrefersEnglish() {
			return langEN
		}
		return langZH
	}
}

func setActiveLanguage(lang string) {
	if resolveLanguage(lang) == langEN {
		activeLangCode.Store(1)
	} else {
		activeLangCode.Store(0)
	}
}

func currentLang() string {
	if activeLangCode.Load() == 1 {
		return langEN
	}
	return langZH
}

func isEnglish() bool {
	return activeLangCode.Load() == 1
}

func tr(zh, en string) string {
	if isEnglish() {
		return en
	}
	return zh
}

func trf(zhFmt, enFmt string, args ...any) string {
	if isEnglish() {
		return fmt.Sprintf(enFmt, args...)
	}
	return fmt.Sprintf(zhFmt, args...)
}

func setLabelText(lbl *walk.Label, text string) {
	if lbl != nil {
		_ = lbl.SetText(text)
	}
}

func setButtonText(btn *walk.PushButton, text string) {
	if btn != nil {
		_ = btn.SetText(text)
	}
}
