# Hev Apple arm64 构建证据

本记录只证明本地评估闭包可以按锁定工具链构建并链接；它不代表人工许可
批准、App 分发批准、真机通流或生产替换。

## 锁定输入

- candidate：`a404c11cd61d8e29e6f4c590b7e659d127fb843e`
- candidate tree：`13bd01e855bc554c245aaf33a0ec587cd71741ce`
- vendored tree SHA-256：`415cbcdc2fcbcb8e439b3c39170ae24fa0c9ce549f1be6192f45de67b034de75`
- Xcode：`26.6 (17F113)`
- SDK：`iphoneos 26.5`
- deployment target：`iOS 17.0`
- target：`arm64-apple-ios`
- 本地 patch：`packetflow-backend-and-readiness-hooks`

## 执行结果

在 `core` 仓库执行两次独立 clean build：

```sh
bash build/folo_build_hev_apple.sh
```

两次退出码均为 `0`。脚本每次先删除当前 candidate + vendor digest 的明确产物
目录，再编译 Hev、任务系统、YAML、lwIP 和公开包装层。最终静态库两次均为
`675432` bytes，SHA-256 均为：

```text
6063d0d00b8f7434561b26ed73023b881ec197899652e2bc4d26be03bb87d94e
```

静态符号检查通过：

```text
_FoloHevPacketFlowStart
_FoloHevPacketFlowState
_FoloHevPacketFlowStop
```

链接夹具检查通过：

```text
Mach-O 64-bit executable arm64
platform 2
minos 17.0
sdk 26.5
```

归档时间字段在构建脚本中被规范化，以消除 Apple `ar`/`libtool` 的墙上时钟
差异；对象内容、来源树和编译输入未被篡改。构建日志和清单写入被忽略的
`artifacts/hev/<candidate>-<vendorTreeSha256>/` 目录，不进入 App 分发路径。

## 未验证项

- 端点仍是公开 API 创建后显式交给核心的评估接口；尚未完成 PacketFlow v1
  12-byte framing、有限队列、真实代理通流和生命周期故障注入。
- 未执行实体设备安装、签名、网络通流或 A/B 压测。
- `compliance/HEV_DEPENDENCY_APPROVAL_V1.yml` 的人工许可审查仍为 pending。

## 后续 wrapper ownership 复测（2026-09-04）

为让 iOS Staging driver 在失败路径也保持单一 descriptor 所有者，wrapper 现在
对调用方传入的 stream peer 执行 `dup`：调用方保留并关闭原 descriptor，Hev
worker 独占并关闭副本，包含初始化失败和 stop 路径。该变化不打开或发现任何
系统 tunnel descriptor。

变更后重新执行同一锁定构建，结果仍为 `hev_apple_build=pass`；归档为
`676328` bytes，SHA-256 为：

```text
5372d152321c3dfcbd2e707b16f881547ff4d358c03162863d6f59ea48b508c1
```

三个 Hev ABI 符号和 `platform 2 / minos 17.0 / sdk 26.5` 链接夹具继续通过。

## 当前 wrapper 归档复测（2026-09-04）

Core `5b30922f4b9f4f1266a3b856d79a7dd08aae1c95` 增加 Hev 配置解析失败时的
worker-return 唤醒路径和 worker 已退出时的幂等 Stop 清理，并由 host fixture 验证
畸形配置返回 `FOLO_HEV_PACKETFLOW_START_FAILED`、状态回到 `IDLE`，以及引擎先
退出后 wrapper Stop 的清理路径。重新执行
`bash build/folo_build_hev_apple.sh`，结果为 `hev_apple_build=pass`；当前静态库
为 `676440` bytes，SHA-256 为：

```text
f3b5e31517a14daa4947817ae868f0466eff4ad89034dcc798ea7e9dcdd5f548
```

ABI 符号、iOS arm64 链接夹具和 host native-first stop 回归继续通过。该归档仍
是未签名、local-only 评估输入。
