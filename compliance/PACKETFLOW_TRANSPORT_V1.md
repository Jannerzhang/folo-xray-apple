# PacketFlow transport seam v1

状态：`IMPLEMENTED / STAGE-13-A`。

本文档定义公开 MPL wrapper 给私有 PacketFlow adapter 的最小出站传输边界。
它不是通用 Xray SDK，也不允许从 App 或 Extension 传入任意 JSON。

## 前置条件

调用方必须先用 `FoloXrayValidateConfigJSON` 校验并用
`FoloXrayStartJSON` 启动已批准的 Folo profile。所有 transport API 在引擎
未处于 `running` 时返回 `FOLO_XRAY_INVALID_STATE`。

## TCP

`FoloXrayTCPConnect(address, length, port, handle)` 使用已运行 Xray instance
的 dispatcher 建立一个 TCP outbound；地址只能是 IP literal 或 ASCII DNS
name，端口为 `1..65535`。返回的 opaque handle 只能用于对应的 Read/Write/
Close，最大同时 session 数为 256。

## UDP

`FoloXrayUDPConnect(handle)` 创建一个 dispatcher-backed UDP session。
`FoloXrayUDPWrite` 只接受 IP literal 目的地址，`FoloXrayUDPRead` 同时返回
payload、源地址 family、源地址 bytes 和源端口，供私有 IP stack 重建完整
IPv4/IPv6 UDP packet。调用方为地址缓冲区提供至少 16 bytes 容量；IPv4 只写入
前 4 bytes。每个 payload 不得超过 65535 bytes。

## 生命周期和错误

- `FoloXrayStop` 会先关闭全部 TCP/UDP handles，再关闭 Xray instance；
- Close 只关闭调用方指定的 handle，调用未知 handle 返回 invalid argument；
- 阻塞 Read 会因 Close/Stop 解除；
- 传输 API 只返回稳定状态码，不跨 ABI 返回 Xray 原始错误、节点凭据或配置；
- wrapper 不创建 TCP/UDP listener，不扫描 fd，不读取私有 Network Extension 状态。

## 验证范围

`main/folotun/transport_test.go` 使用 Xray dispatcher 的受控 freedom outbound
验证 TCP 和 UDP payload 的真实出站/回包；该测试不等于 VLESS Reality 真机
证据。真实 IP packet 到 TCP/UDP session 的转换由私有 MIT/Apache 网络栈和
阶段 13-B/13-C 完成，真实设备与 Reality 节点仍是阶段 13-D 人工门禁。
