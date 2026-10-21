# TmkNetworkLAN 图标

唯一原图为 `tmknetworklan-icon.png`，透明背景，淡亮蓝色刷痕 T。

2026-10-18 使用内置 imagegen 编辑原深蓝图标，保留 T 的轮廓、比例、居中构图、笔触和透明背景。编辑提示：仅将深蓝笔触改为约 `#70C9FF` 的淡亮天蓝，保留 `#56B5F0` 至 `#A0DDFF` 的纹理层次，不增加背景、文字、阴影、光晕或边框。

同步途径：

- `cmd/client/winres.json` 从此图生成 Windows `APP` 图标资源，供 EXE、窗口标题栏、版本窗口和自定义弹窗使用。
- `cmd/client/ui_windows.go` 从发布目录的同名 PNG 加载加入页、侧栏及版本信息页品牌图。
- `build-windows-client.ps1` 每次重新生成 `.syso`、编译 EXE、复制 PNG 并生成发布 ZIP；缺少资源生成工具时会报错，避免旧图标被继续打包。

原深蓝版本备份在本地忽略目录 `.tmp-runtime/icon-before-lightblue-20261018-131336/`，不随发布包分发。
