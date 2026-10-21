//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

func (a *desktop) exportFRPProfile() {
	if a.frpManager == nil {
		a.showFRPError("导出穿透配置", errors.New("当前没有可导出的穿透配置"))
		return
	}
	cfg, ok := a.frpManager.Config()
	if !ok {
		a.showFRPError("导出穿透配置", errors.New("请先保存服务器和规则后再导出"))
		return
	}
	data, err := frpctl.EncodeConfig(cfg)
	if err != nil {
		a.showFRPError("导出穿透配置", err)
		return
	}
	name := cfg.Profile.Name
	if name == "" {
		name = cfg.Profile.ID
	}
	name = strings.Map(func(r rune) rune {
		switch r {
		case '\\', '/', ':', '*', '?', '"', '<', '>', '|':
			return '-'
		}
		return r
	}, name)
	fd := walk.FileDialog{
		Title:       "导出 TLAN 穿透配置",
		FilePath:    filepath.Join("", name+".frp-profile.json"),
		Filter:      "TLAN 穿透配置 (*.json)|*.json|所有文件 (*.*)|*.*",
		FilterIndex: 1,
	}
	accepted, err := fd.ShowSave(a.window)
	if err != nil {
		a.showFRPError("导出穿透配置", err)
		return
	}
	if !accepted {
		return
	}
	path := fd.FilePath
	if filepath.Ext(path) == "" {
		path += ".json"
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		a.showFRPError("导出穿透配置", err)
		return
	}
	a.showNotice(clientui.Feedback{
		Title:   "穿透配置已导出",
		Message: "文件只包含受限配置和 secret 引用，不包含 token、CA 私钥、访问密码或私有密钥。",
		Detail:  path,
	})
}

func (a *desktop) importFRPProfile() {
	if a.frpBusy || a.frpManager == nil {
		return
	}
	fd := walk.FileDialog{
		Title:       "导入 TLAN 穿透配置",
		Filter:      "TLAN 穿透配置 (*.json)|*.json|所有文件 (*.*)|*.*",
		FilterIndex: 1,
	}
	accepted, err := fd.ShowOpen(a.window)
	if err != nil {
		a.showFRPError("导入穿透配置", err)
		return
	}
	if !accepted {
		return
	}
	info, err := os.Stat(fd.FilePath)
	if err != nil {
		a.showFRPError("导入穿透配置", err)
		return
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > frpctl.MaxConfigBytes {
		a.showFRPError("导入穿透配置", fmt.Errorf("配置文件必须是非空普通文件且不超过 %d 字节", frpctl.MaxConfigBytes))
		return
	}
	data, err := os.ReadFile(fd.FilePath)
	if err != nil {
		a.showFRPError("导入穿透配置", err)
		return
	}
	current, hasCurrent := a.frpManager.Config()
	var currentPtr *frpctl.Config
	if hasCurrent {
		currentCopy := current
		currentPtr = &currentCopy
	}
	analysis, err := frpctl.AnalyzeConfigImport(data, currentPtr)
	if err != nil {
		a.showFRPError("导入穿透配置", err)
		return
	}
	if !analysis.Supported {
		a.showFRPError("导入穿透配置", errors.New(analysis.RejectText()))
		return
	}
	imported := analysis.Config
	if hasCurrent {
		imported.Profile.ID = current.Profile.ID
		imported.Profile.Revision = current.Profile.Revision
	} else {
		imported.Profile.ID = a.frpProfileID
		imported.Profile.Revision = 0
	}
	if err = frpctl.ValidateConfig(imported); err != nil {
		a.showFRPError("导入穿透配置", err)
		return
	}
	message := fmt.Sprintf("将用“%s”替换当前配置并重新校验服务器连接。\n\n%s\n\nToken、CA 私钥、访问密码和私有密钥不会从文件导入；必须已存在于当前配置档。未知、危险或不支持的字段会被拒绝。是否继续？", imported.Profile.Name, analysis.PreviewText())
	if walk.MsgBox(a.window, "导入穿透配置", message, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	a.applyFRPConfig(imported, "")
}
