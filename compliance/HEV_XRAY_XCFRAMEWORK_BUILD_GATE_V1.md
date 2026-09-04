# Hev + Xray 完整 Apple 核心产物门禁（阶段 21）

日期：2026-09-04。

状态：`BLOCKED`。

## 实测命令

在干净的独立 core worktree 执行：

```sh
bash build/folo_build_xcframework.sh
```

退出码：`1`。

门禁输出：

```text
build error: Xcode 26.6 does not match 26.4
```

`build/toolchain.lock.yml` 固定 Xcode `26.4`、build `17E192` 和 iPhoneOS
SDK `26.4`；当前主机为 Xcode `26.6`、build `17F113`、SDK `26.5`。为保持
工具链可复现性，本阶段不修改锁文件、不更换全局工具链，也不把 Hev 单架构
评估归档冒充完整 Xray XCFramework。

## 影响与后续

完整 `FoloXray.xcframework`（iOS 与 simulator slices）未由本次命令生成，
因此 iOS 宿主 App/Packet Tunnel 联合构建、符号闭包和嵌入验证未执行。待释放
匹配锁文件的隔离 Xcode 工具链后，应重新运行核心构建、记录 artifact manifest
与 hash，再由 iOS 阶段门禁消费；本记录不授权签名、安装、发布或生产替换。
