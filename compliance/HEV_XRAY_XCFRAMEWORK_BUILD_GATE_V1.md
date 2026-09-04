# Hev + Xray 完整 Apple 核心产物门禁（阶段 21）

日期：2026-09-04。

状态：`PASS`（后续复测；原始工具链阻塞已解除）。

## 实测命令

首次执行在干净的独立 core worktree 被工具链检查阻塞。随后仅在本路线分支
`codex/hev-xray-core` 内完成工具链锁定对齐，并将 Hev wrapper 移到独立的
`apple-wrapper/hev/` 评估路径，避免它被 Xray Go package 自动纳入 XCFramework
编译。之后在同一分支执行以下复测：

```sh
bash build/folo_build_xcframework.sh
```

退出码：`0`（复测）。

门禁输出：

```text
xcframework_build=pass
```

复测使用 Xcode `26.6`、build `17F113` 和 iPhoneOS SDK `26.5`，并由
`build/toolchain.lock.yml` 固定这些主机上实际可用的版本。复测产物的 source
revision、upstream lock SHA、slice 信息、导出符号和归一化 XCFramework SHA
均记录在 `artifact-manifest.yml`；设备 slice 为 arm64，simulator slice
为 x86_64+arm64。Hev 仍保持独立的 local-evaluation-only Apple arm64 产物，
不冒充完整 Xray XCFramework。

## 影响与后续

复测已生成完整 `FoloXray.xcframework`（iOS 与 simulator slices），并已由
iOS 分支消费完成输入哈希、link probe、extension probe、未签名 Packet Tunnel
target 和未签名宿主 App 的静态门禁。当前证据仍不包含 Network Extension
真实通流、实体设备 A/B、长期运行、人工许可批准或签名/安装/发布；这些门禁
继续由 iOS 阶段 22/23 管理。本记录不授权生产替换。
