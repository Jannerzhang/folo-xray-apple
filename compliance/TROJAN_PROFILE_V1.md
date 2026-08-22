# Folo Trojan 候选配置边界

状态：`local-only / releaseReady=false`。

本记录对应阶段 38 的本地数据面闭包，不代表 Trojan 已经进入首发或可以在 App Store 版本中请求。

## 允许的输入

- Folo profile `version=2`。
- `mode=tun`。
- 单一 `outbound.protocol=trojan`。
- TCP 传输和标准 TLS，必须提供受控 `serverName`。
- 服务端按 assignment/租约签发的短期 password；该 password 不得复用登录密码。
- 由 Packet Tunnel 复用既有受保护 App Group profile 和 Xray dispatcher；不创建本地 listener。

## 明确拒绝

- 通用 Xray JSON、Clash YAML、分享链接、二维码、订阅 URL 和用户任意导入。
- Reality、WebSocket、gRPC、HTTPUpgrade、QUIC、mKCP、明文 TCP 或 TLS 跳过证书校验。
- VLESS 的 UUID、flow、encryption 或 Reality 对象混入 Trojan profile。
- 长期保存或日志输出 password、节点地址、SNI 和完整 runtime profile。
- 连接失败后的直连、静默切换到 VLESS 或其他协议。

## 来源与许可证

- 实现来源：仓库已锁定的 `github.com/xtls/xray-core` v1.8.24，具体 commit 见 [`upstream.lock.yml`](../upstream.lock.yml)。
- 许可证：Xray core `MPL-2.0`，许可证文件为 `upstream/xray-core/LICENSE`；修改的 Folo parser、distro 注册和构建差异继续在公开仓库记录。
- 传递依赖：由 `scripts/check_license_boundary.sh` 和 `go-licenses` 门禁复核；出现 GPL/AGPL/LGPL/SSPL/BUSL/未知来源时阻断。
- 公开义务：该候选使用公开 MPL 核心仓库的源代码和构建脚本；私有 Swift UI、账户、权益和业务代码不放入公开核心仓库。

## 发布门禁

服务端能力响应必须保持：

```text
releaseReady = false
clientMayRequest = false
```

在以下证据全部存在前不得改为可请求：受控 Trojan 节点 TCP/TLS/SNI 互操作、错误证书和错误 password fail-closed、真实签名设备 Packet Tunnel 通流、资源峰值、Reality 回归、SBOM/Notice 更新、许可证负责人批准和回滚演练。
