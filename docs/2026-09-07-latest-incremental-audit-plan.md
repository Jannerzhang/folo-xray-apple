# 最新增量审核修复计划

基线：`codex/xray-rust-core-eval`（Core `aa42c98`），包含阶段 13–16 的未提交工作树内容；本文件位于阶段 17 独立分支。

## 阶段 17：引擎选择与发布证据门禁

- 与 App 统一 immutable artifact identity、source/license/security/device/PacketFlow 证据。
- 保持 artifact 不存在或未签名时 `releaseReady=false`，不把脚本/目录通过当作产物存在。

## 阶段 18：跨仓库 golden fixture 与配置链路

- Rust parser 使用与 App 完全相同的 fixture；覆盖 block/direct、IPv4/IPv6 和错误输入。
- 增加可执行 parser/runtime 配置检查；真实协议服务端互通作为设备门禁单独记录。

## 阶段 19：资源预算与采样有效性

- 将 FoloIOS 的 TUN、flow、DNS、runtime task 和物理字节预算写入可审计的 Core profile/manifest。
- 输出 queue/flow/drop/peak 数据所需的统计接口，但不把未运行设备的值伪装成通过。

## 阶段 20：合规事实源与路由输入校验

- 依赖、source lock、ABI、SBOM、artifact manifest 使用同一 commit/artifact 状态。
- parser 对 IP/CIDR 和地址族做严格、可测试的输入验证。

## 阶段 21：性能/真机发布门禁

- 将 FFI 性能测试升级为 bounded stress/soak harness，严格检查状态码、回复数、drop、峰值和 stop。
- 真实 iOS 设备、签名 XCFramework、受控 VLESS/Reality/Vision/XUDP 服务端和长时门禁只在发布环境执行，不在本地测试中虚报。
