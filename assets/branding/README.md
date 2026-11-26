# TLAN 图标

唯一原图为 `tlan-icon.png`，透明背景，淡亮蓝色刷痕 T。

同步途径：

- `cmd/client/winres.json` 从此图生成 Windows `APP` 图标资源，供 EXE、窗口标题栏、版本窗口和自定义弹窗使用。
- `cmd/client/ui_windows.go` 从发布目录的同名 PNG 加载加入页、侧栏及版本信息页品牌图。
- `build-windows-client.ps1` 每次重新生成 `.syso`、编译 EXE、复制 PNG 并生成发布 ZIP；缺少资源生成工具时会报错，避免旧图标被继续打包。
