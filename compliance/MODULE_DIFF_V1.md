# Folo 首发模块差异与资源预算

状态：`local-only`。本记录对应阶段 09 的第一版模块裁剪，不代表已完成真机 Packet Tunnel 门禁。

## 依赖闭包变化

| 指标 | 阶段 08 基线 | 阶段 09 目标闭包 | 说明 |
| --- | ---: | ---: | --- |
| `go list -deps github.com/xtls/xray-core/main/distro/folo` | 571 | 389 | 以生产目标包为边界，不计测试包 |
| 阶段 38 Trojan 候选闭包 | 389 | 391 | 增加已锁定 Xray MPL Trojan outbound 与严格 Folo parser 分支；仍不代表默认可请求 |
| 阶段 39 VMess 候选闭包 | 391 | 402 | 增加已锁定 Xray MPL VMess outbound 与严格 AEAD/TCP/TLS Folo parser 分支；仍不代表默认可请求 |
| 通用 JSON / `infra/conf` | 进入闭包 | 0 | 改为 `main/folojson` 严格版本化 schema |
| Xray 本地 inbound listener manager | 进入闭包 | 0 | 改为 `main/foloinbound` 空 manager |
| API / command server | 进入闭包 | 0 | 不注册 command 配置或 gRPC API |
| observatory / metrics server / reverse | 进入闭包 | 0 | 首发不提供服务端管理面 |
| VLESS outbound | 保留 | 保留 | 首发默认代理协议出口 |
| Trojan outbound | 未进入 | 按 gated profile 进入 | 仅 TCP + 标准 TLS + serverName + 短期 password；服务端默认关闭 |
| TCP + Reality + TLS/uTLS | 保留 | 保留 | Reality/Vision 首发路径 |
| stats manager | 保留 | 保留 | 仅供封装层读取受控计数 |

阶段 09/38/39 的模块门禁由 [`scripts/audit_first_release_modules.sh`](../scripts/audit_first_release_modules.sh) 执行。脚本同时断言必须保留的注册包和禁止出现的包路径；Trojan 与 VMess 只通过版本化 Folo JSON 入口进入，构建脚本会把结果复制到每个本地 artifact manifest 目录。服务端与客户端仍默认只请求 VLESS/Reality。

本阶段本地审计结果：`dependency_count=391`、`go test` 通过、`license_boundary=pass`。公开 artifact 只有在干净提交上重新构建并更新 manifest 后，才可作为本阶段的构建输入；当前仍为 `localOnly`，不构成发布授权。

## 配置边界

首发不再接受任意 Xray JSON。应用层只生成 `compliance/fixtures/folo-vless-reality-v1.json` 所示的 Folo schema：

首发 `version=1`、`mode=tun`、单一 VLESS outbound、TCP、Reality、`xtls-rprx-vision` 和 `encryption=none`；候选 Trojan 使用 `version=2`、显式 `protocol=trojan`、TCP、标准 TLS、serverName 和短期 password；候选 VMess 使用 `version=3`、显式 `protocol=vmess`、AEAD、`alterId=0`、TCP、标准 TLS 和 serverName。

解析器拒绝未知字段、非 Reality 安全类型、非 TCP 传输、多个出口概念、监听器字段和超出大小上限的配置。Packet Tunnel 自有 TUN/socket adapter 不通过 Xray 的监听器实现注册。

## 资源预算

阶段 08 构建测得的静态库尺寸为：设备 `30,758,296` bytes，模拟器 fat slice `60,021,480` bytes。阶段 09 的同一提交干净重建产物为：设备 `17,539,696` bytes（减少 `42.98%`），模拟器 fat slice `34,537,680` bytes（减少 `42.46%`）。实际记录位于本地 artifact manifest：

`artifacts/xcframework/801752a43822d144b9b0920ae85eb3a03f3815a7/artifact-manifest.yml`

本地构建还完成了 XCFramework 和 manifest 的 `diff -rq`/文本比对，结果为 `reproducible_build=pass`。产物仍为 `localOnly=true`、`releaseReady=false`，不提交二进制、不推送远端。

构建证据摘要：

| 字段 | 值 |
| --- | --- |
| source revision | `801752a43822d144b9b0920ae85eb3a03f3815a7` |
| Go / Xcode / SDK | `go1.26.4` / `26.4.1 (17E202)` / `26.4` |
| iOS deployment target | `17.0` |
| device static library SHA-256 | `72464cb10fb19d58e02c18240a33c62a655741e01c6f4f8c738419306648fe0d` |
| simulator static library SHA-256 | `b56164a3731beb7dfdc9d5a030d3c3ab94da687b4eec4754f16a45ff2ce6889d` |
| normalized XCFramework SHA-256 | `7764a15b0f3050c526fdb220bdfeaee831b09eaccd2aedc3118f70c9edd5c687` |

移动端运行预算记录在 [`mobile-tuning-v1.yml`](mobile-tuning-v1.yml)：配置上限 4 MiB、单实例、零 Xray 网络 listener、峰值内存目标 15 MiB，25 MiB 为升级调查阈值。内存数值必须在后续真机 Packet Tunnel soak 中测量，不能由 Go 依赖数量推断。

## 回滚点

阶段 09 的回滚只允许恢复上一份公开内核提交和 `distro-v1.yml`，不允许在私有客户端中重新 import 通用 Xray 配置或被排除模块。任何协议恢复都要新增 patch series 条目、许可证审计、二进制 SBOM 和预算修订。
