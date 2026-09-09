# Rust Core 单轨化与旧 Go 内核退役计划

## 目标

- 让公共内核仓库的 Apple artifact、CI、发布和合规入口统一使用当前 `xray-rust-eval` 的 Rust `xray_ffi` ABI v2。
- 删除旧的 Go/cgo Apple wrapper、gVisor netstack、旧 `FoloXray*` ABI、Go workspace 和只服务旧发布链路的源码/脚本/合规资料。
- 保留 Rust 仓库中仅用于固定 oracle/互操作测试的 Go 工具，并明确其不是发布运行时或 Apple artifact 输入。
- 让 iOS 客户端使用的 `XrayRust.xcframework`、header、module map、source lock 和发布 manifest 来自同一 Core 提交。

## 阶段与验收

1. 行为锁定：记录当前 Rust workspace、ABI header、现有 artifact verifier 和客户端消费契约。
2. 旧路径删除：移除 `apple-wrapper/`、旧 upstream Go workspace、cgo build/link fixture、Go license boundary 和 gVisor notice。
3. Rust 发布收敛：以 `xray-rust-eval` 的 Rust 构建脚本生成 `XrayRust.xcframework`，更新 CI、release bundle、SBOM、source lock 和 ABI 校验。
4. 合规与文档：删除旧 Go patch/发布叙述，补充 test-only oracle 边界和 Rust Core release 说明。
5. 全量验证：运行 Rust formatter/clippy/tests、Apple artifact/link gate（可用时）、Ruby/Shell/JSON/YAML 门禁，并检查旧运行时符号和入口不存在。

## 保持不变

- `xray-rust-eval` 的 Rust 协议、TUN、FFI 运行时行为和 ABI v2 不做功能重写。
- 不修改客户端仓库、不删除 App Group/Keychain/StoreKit 数据、不改变 iOS profile 或 VPN 生命周期契约。
- `xray-rust-eval` 内为可重复 ClientHello/masquerade/gRPC fixture 提供参考答案的 Go oracle 仅作为测试依赖保留；它不得出现在 Apple artifact、发布构建或运行时依赖图中。

## 回滚与兼容性

- 所有修改仅在新 worktree 和 `feat/custom-ios-v5-rm-go-core-` 前缀分支中进行。
- Rust source/header/tree/hash/ABI 任一不一致时 fail-closed，停止 artifact 发布，不恢复 Go wrapper 作为回退。
- 如旧 Go 资料仍需审计，应通过 Git 历史追溯，不重新放回活动构建或发布路径。
