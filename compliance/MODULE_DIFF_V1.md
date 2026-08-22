# Folo 首发模块差异与资源预算

状态：`local-only`。本记录对应阶段 09 的第一版模块裁剪，不代表已完成真机 Packet Tunnel 门禁。

## 依赖闭包变化

| 指标 | 阶段 08 基线 | 阶段 09 目标闭包 | 说明 |
| --- | ---: | ---: | --- |
| `go list -deps github.com/xtls/xray-core/main/distro/folo` | 571 | 389 | 以生产目标包为边界，不计测试包 |
| 通用 JSON / `infra/conf` | 进入闭包 | 0 | 改为 `main/folojson` 严格版本化 schema |
| Xray 本地 inbound listener manager | 进入闭包 | 0 | 改为 `main/foloinbound` 空 manager |
| API / command server | 进入闭包 | 0 | 不注册 command 配置或 gRPC API |
| observatory / metrics server / reverse | 进入闭包 | 0 | 首发不提供服务端管理面 |
| VLESS outbound | 保留 | 保留 | 唯一代理协议出口 |
| TCP + Reality + TLS/uTLS | 保留 | 保留 | Reality/Vision 首发路径 |
| stats manager | 保留 | 保留 | 仅供封装层读取受控计数 |

阶段 09 的模块门禁由 [`scripts/audit_first_release_modules.sh`](../scripts/audit_first_release_modules.sh) 执行。脚本同时断言必须保留的注册包和禁止出现的包路径；构建脚本会把结果复制到每个本地 artifact manifest 目录。

## 配置边界

首发不再接受任意 Xray JSON。应用层只生成 `compliance/fixtures/folo-vless-reality-v1.json` 所示的 Folo schema：

`version=1`、`mode=tun`、单一 VLESS outbound、TCP、Reality、`xtls-rprx-vision` 和 `encryption=none`。

解析器拒绝未知字段、非 Reality 安全类型、非 TCP 传输、多个出口概念、监听器字段和超出大小上限的配置。Packet Tunnel 自有 TUN/socket adapter 不通过 Xray 的监听器实现注册。

## 资源预算

阶段 08 构建测得的静态库尺寸为：设备 `30,758,296` bytes，模拟器 fat slice `60,021,480` bytes。阶段 09 的首要硬门禁是依赖闭包和本地 listener/API 清除；静态库尺寸目标暂沿用该基线，待裁剪后的 XCFramework 构建完成后用实际 manifest 覆盖，不以“估计节省”替代测量。

移动端运行预算记录在 [`mobile-tuning-v1.yml`](mobile-tuning-v1.yml)：配置上限 4 MiB、单实例、零 Xray 网络 listener、峰值内存目标 15 MiB，25 MiB 为升级调查阈值。内存数值必须在后续真机 Packet Tunnel soak 中测量，不能由 Go 依赖数量推断。

## 回滚点

阶段 09 的回滚只允许恢复上一份公开内核提交和 `distro-v1.yml`，不允许在私有客户端中重新 import 通用 Xray 配置或被排除模块。任何协议恢复都要新增 patch series 条目、许可证审计、二进制 SBOM 和预算修订。
