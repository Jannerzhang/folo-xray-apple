# Folo VMess 候选配置边界

状态：`local-only / releaseReady=false`。

本记录对应阶段 39 的本地数据面闭包，不代表 VMess 已进入首发或可以在
App Store 版本中请求。

## 唯一实现选择

- 选择：锁定 Xray v1.8.24 中的 `proxy/vmess/outbound`，通过 Folo 自有
  版本化 JSON parser 建立唯一入口。
- 不引入 V2Fly 或其他第二套 VMess 实现，不复制分享链接解析器，不打包
  通用 Xray JSON/`infra/conf`。
- 许可证：Xray core 为 `MPL-2.0`；修改的 parser、distro 注册和构建差异
  在公开仓库 patch series 中记录。

## 允许的输入

- Folo profile `version=3`、`protocol=vmess`、`mode=tun`。
- UUID、AEAD security `auto`/`aes-128-gcm`/`chacha20-poly1305`，并隐含
  `alterId=0`；profile 不接受 `alterId` 字段。
- TCP 传输、标准 TLS、明确的 `serverName`；本阶段不加入 WebSocket，
  以便单独完成 transport 互操作和资源审批。
- assignment/lease 约束的短期 proxy identity UUID，不作为账户登录密码。

## 明确拒绝

- legacy `alterId`、`none`/`zero`/未知 VMess encryption 和未知 security。
- WebSocket、gRPC、HTTPUpgrade、QUIC、mKCP、明文 TCP、TLS 跳过证书验证
  或任意自定义传输参数。
- Trojan password、VLESS flow/encryption、Reality 对象或通用 Xray 字段混入
  VMess profile。
- 分享链接、二维码、订阅 URL、用户任意导入和失败后的直连/静默降级。

## 发布门禁

服务端能力响应必须保持：

```text
releaseReady = false
clientMayRequest = false
```

在以下证据全部存在前不得改为可请求：受控 VMess AEAD/TCP/TLS 节点互操作、
TLS/SNI 和错误凭据 fail-closed、真实签名设备 Packet Tunnel 通流、资源峰值、
VLESS/Trojan 回归、SBOM/Notice 更新、许可证负责人批准和回滚演练。
