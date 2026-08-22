# PacketFlow v1 公共端点记录

状态：`local-only`、`PoC`。本记录对应阶段 10，不代表已完成真实 VLESS/TUN 数据面或真机门禁。

## 公共边界

公开内核提供 `main/folotun`，Apple wrapper 提供以下受控 ABI：

- `FoloXrayPacketBridgeStart(int32_t fd)`：接收一个已创建的 POSIX `SOCK_STREAM` socketpair 端点；成功后 wrapper 负责该端点的重复关闭保护。
- `FoloXrayPacketBridgeStop()`：取消 loopback pump，关闭 endpoint，幂等返回。
- `FoloXrayPacketBridgeState()`：返回 idle/running 状态。
- `FoloXrayPacketBridgeCopyStatsJSON()`：返回不含 payload 的 frame/byte 计数。

公开端点不扫描 fd、不使用 KVC、不调用 Network Extension 私有 API、不创建本地 TCP/UDP/SOCKS listener。它只验证 framing 和双向 packet transport；真实 `NEPacketTunnelFlow` 侧在私有 `folo-ios` 仓库实现。

## framing v1

固定头 12 bytes，整数 big-endian：`magic(0x46,0x50)`、`version(1)`、`family(4/6)`、`protocol/next-header`、reserved flags、payload length、reserved sequence。payload 必须是完整 IPv4/IPv6 packet，长度 `1..65535`；解析器验证 IP header length/total length，并验证 header metadata 与 payload 一致。

stream 读取使用 `io.ReadFull`，写入使用循环 full-write。partial read/write、合并帧、截断帧、长度不一致、reserved 非零和未知版本都会失败，不会把一次 stream read 当成一个 packet。

## 实际门禁

| 门禁 | 结果 |
| --- | --- |
| Go `main/folotun` 单元测试 | PASS；IPv4/IPv6、partial read/write、截断、metadata 和 malformed IP |
| Swift `FoloPacketFlowBridge` 测试 | PASS；IPv4/IPv6、socketpair 双向 echo、重复 stop |
| 生产依赖闭包 | PASS；`main/distro/folo` 390 项，原阶段 09 为 389 项 |
| 导出符号 | PASS；13 项 allowlist，含 4 项 PacketBridge ABI |
| iOS link fixture | PASS；iOS 17.0 / SDK 26.4 |
| 两次干净 XCFramework 构建 | PASS；framework 与 manifest `diff` 一致 |
| 许可证门禁 | PASS；无 GPL/AGPL/LGPL/SSPL/BUSL/Commons Clause |

本地 artifact revision：`c9b67ac9b4bf9ee686e65d0d181586fb1d7a7a18`，本地 tag：`app-v0.0.0-core.5`。

设备静态库为 `17,584,896` bytes，SHA-256 为 `0c7e2e5a759b1a81433d49251e46f8da514b83be0f00933121c9c5eae3b835c0`；模拟器 fat 静态库为 `34,607,688` bytes，SHA-256 为 `6078cdda1e66cc1e6f966a2bb50953fb8e11b682ad34027cb0bc03368845e0d3`；规范化 XCFramework SHA-256 为 `28ea9993c77ca7dceaa373a191fce3d36ce9351df9a08488b0b8041686b63280`。

## 明确限制

阶段 10 的 loopback handler 不是代理能力。它不将原始 IP packet 转为 TCP/UDP socket，也不执行 DNS、规则路由或 VLESS；这些内容属于阶段 12/13，若无法在公开 API 与合规内核边界内完成，必须将后续阶段标为 `FAILED_GATE`，不得用 loopback 结果冒充真实通流。
