# Folo iOS 客户端与网络内核全闭源可行性及合规审核报告

> **报告日期**：2026 年 9 月 10 日  
> **审计对象**：
> 1. iOS 客户端：`/Users/barneszhang/Documents/UGit/folo-hev-xray/ios`（仓库：`Jannerzhang/folo-ios`）  
> 2. 网络内核：`/Users/barneszhang/Documents/UGit/folo-xray-rust-eval/core`（仓库：`Jannerzhang/folo-xray-apple`）  
> **核心议题**：项目当前客户端与内核，此前为过审与符合开源及苹果要求将内核开源，现评估是否能将项目“全转化成私有项目闭源”。

---

## 一、 执行摘要与结论

| 审核模块 | 能否转为私有闭源 | 核心原因与法律/审核边界 |
| :--- | :---: | :--- |
| **iOS 客户端 (`folo-ios`)** | **完全可以（现已是闭源设计）** | 客户端 Swift 代码 100% 为自主研发，受专有版权保护。苹果 App Store 从不强制应用开源。GitHub 仓库可随时设为 Private。 |
| **网络内核 (`core / xray-rust`)** | **不可直接闭源（法律禁止）** | 当前内核基于上游开源项目 `xray-rust`，遵循 **MPL-2.0** 许可证。MPL-2.0 强制要求在分发二进制时必须开源受覆盖文件的源码并提供 Source Offer。Folo 并非上游唯一版权人，无权擅自更改协议闭源。 |
| **整套系统综合结论** | **不可“全量”闭源，但可实现“核心商业资产 100% 闭源”** | 推荐维持并规范当前的**“分层隔离架构”**：客户端（业务、UI、支付、API）保持**私有闭源**；内核仅作为公开开源的通用网络底座。若执意内核全闭源，必须彻底重写剔除所有 MPL 代码。 |

---

## 二、 苹果 App Store 审核要求澄清

在历史开发过程中，团队存在一种印象：“*为了苹果过审，符合开源和苹果要求，将内核开源了*”。经本次对苹果政策与项目演进历史的深度审核，澄清如下：

1. **苹果从不要求 App 开源**：
   - 苹果 App Store 99% 以上的应用均为商业闭源专有软件。
   - 苹果《App Store 审核指南》（App Review Guidelines）**没有任何条款强制要求开发者公开客户端或底层模块的代码**。

2. **当初必须开源内核的真实原因**：
   - **开源许可证的强制法律义务（MPL-2.0 Copyleft）**：内核使用了来自社区的 `xray-rust`（基于 MPL-2.0 授权）及 Xray 生态。MPL-2.0 规定：一旦以可执行格式（即编译成 `.xcframework` 并随 iOS App 上架）向公众分发软件，**必须以源代码形式向接收者提供该核心代码及其修改（Source Offer）**。
   - **苹果《审核指南》第 5.2 条（知识产权与合法性）**：苹果严格禁止侵犯第三方知识产权及开源许可证违规行为。若闭源分发 MPL 核心，原作者或开源维权组织（如 SFC/FSF）可直接向 Apple Legal 提起侵权投诉（DMCA Takedown），苹果将直接**下架 App** 并可能**封禁开发者账号**。
   - **历史 GPL 遗留风险隔离**：早期版本曾存在 GPL 代码污染风险（GPL 与 App Store 协议存在强冲突）。为了合规过审，项目团队进行了干净房间（Clean Room）重构，将客户端彻底与强传染代码剥离，并将网络内核收敛在独立的公开 MPL 仓库中。

---

## 三、 客户端与内核详细审计

### 1. iOS 客户端 (`folo-hev-xray/ios`)

- **代码性质**：
  - 核心 Swift 代码位于 `Sources/` 与 `Xcode/`，包含 `FoloCore`、`FoloShared`、`FoloPacketFlowBridge`、`FoloPacketTunnel` 及宿主 SwiftUI 界面。
  - 项目根目录 `LICENSE.md` 明确声明为专有许可：
    > *"Proprietary notice: Copyright (c) 2026 Folo. All rights reserved. No permission is granted to copy, modify, distribute, sublicense, or create derivative works..."*
- **依赖隔离性**：
  - 严格执行了 `CLEAN_ROOM_POLICY.md` 与 `TARGET_BOUNDARIES_V1.md`。
  - 客户端通过 C ABI 接口动态/静态链接内核 XCFramework，不直接包含任何 GPL/AGPL 强传染源码。
- **闭源可行性**：
  - **100% 可行**。
  - 客户端的代码著作权完全属于团队，不受任何上游开源协议束缚。
  - 该代码库应当保持为 **Private（私有仓库）**，不向任何第三方公开。

---

### 2. 网络内核 (`folo-xray-rust-eval/core`)

- **代码构成与上游来源**：
  - 内核主要模块位于 `xray-rust-eval/crates/`，包括 `xray-core-rs`、`xray-proxy`、`xray-transport`、`xray-tun`、`xray-ffi` 等。
  - 上游来源：`https://github.com/aimalygin/xray-rust`，声明协议为 **MPL-2.0**。
- **关键许可证条款约束（MPL-2.0）**：
  - **Section 3.1（源码分发）**：所有对受覆盖软件（Covered Software）的分发以及任何对其进行的修改（Modifications），必须以 MPL-2.0 源码形式发布。
  - **Section 3.2（二进制分发要求）**：如果分发可执行形式（即 iOS App 中的二进制），必须同时提供源码，并明确告知接收者获取源码的途径（Source Offer）。
  - **Section 3.4（保留声明）**：不得移除任何上游版权声明与许可证说明。
- **附加资产协议约束**：
  - `geoip.dat`：来自 `v2fly/geoip`，采用 **CC BY-SA 4.0（署名-相同方式共享）**，若随 App 静态分发，同样具备严格的开源及共享约束。
  - `geosite.dat`：来自 `v2fly/domain-list-community`，采用 **MIT** 许可证。
- **闭源可行性**：
  - **不可闭源**。
  - 团队不是 `xray-rust` 代码的原始版权人。在未经原作者独家商业授权的情况下，**任何擅自删除 MPL-2.0 声明、隐藏源码、关闭公共仓库的行为，均构成对上游版权的民事侵权**。

---

## 四、 为什么现有“Larger Work”模式是最佳方案？

MPL-2.0 是一种**“文件级弱 Copyleft”**许可证（File-level Weak Copyleft），与 GPL/AGPL 有着本质区别：

1. **允许“更大作品”（Larger Work）采用闭源协议**：
   - 根据 MPL-2.0 第 3.3 条：开发者可以将受覆盖代码与非受覆盖代码组合为一个“更大作品（Larger Work）”，并且该更大作品可以按照开发者选择的任意条款（包括闭源专有商业协议）进行分发。
2. **不传染独立文件**：
   - 客户端独立的 Swift 源码、业务逻辑、UI、API 通信、加密算法配置、StoreKit 交易等，都在独立文件中，**绝不会被 MPL-2.0 传染**。
3. **已落地的合规闭环**：
   - 客户端通过 `OpenSourceNotices.json` 向用户公示开源声明；
   - 公开内核仓库 `folo-xray-apple` 仅提供底层的网络通信实现与 ABI；
   - 这种模式**完美平衡了商业机密保护（客户端 100% 闭源）与开源法律履约（底座内核开源合规）**。

---

## 五、 若必须实现“整套项目 100% 彻底闭源”的唯一路径

如果因公司重大战略或核心机密（例如自研独家抗封锁网络协议），**必须要求内核也完全不向公众开放源码**，唯一合规可行的工程路径如下：

```text
[当前状态: 混合合规]
  ├── iOS 客户端: 闭源私有 (OK)
  └── 网络内核: 基于 xray-rust (MPL-2.0, 必须开源)

[整套彻底闭源目标状态]
  ├── 步骤 1: 全面排查并彻底删除 xray-rust / Xray-core 的全部代码与 Crates
  ├── 步骤 2: 自研或替换为纯宽松许可 (Permissive) 的网络栈
  │           - 仅允许使用 MIT / Apache-2.0 / BSD 协议的基础组件 (如 tokio, rustls, smoltcp)
  │           - 自研 TUN 转发、自研代理协议与 FFI 接口
  ├── 步骤 3: 移除 CC BY-SA 4.0 的 geodata 数据集，改用自研规则或纯 MIT 数据源
  └── 步骤 4: 确认所有代码版权 100% 归公司自有，此时内核方可完全设为私有闭源仓库
```

> ⚠️ **高风险警示**：  
> **严禁在未重写代码的情况下，直接将现有的 `folo-xray-apple` 或 `core` 仓库设为私有**。一旦被上游作者或合规维权者发现并在 App Store 提请侵权下架，将直接导致线上 App 被强行下架并面临法律纠纷。

---

## 六、 最终建议与落地操作指引

1. **客户端仓库权限（立即执行）**：
   - 将 `Jannerzhang/folo-ios` 仓库确认设置为 **Private（私有）**。
   - 保留客户端内的 `LICENSE.md` 专有版权声明，禁止对外公开客户端源码。

2. **网络内核仓库（维持现状）**：
   - `Jannerzhang/folo-xray-apple` 维持 **Public（公开）**，仅包含通用的 Rust 内核、FFI 接口、构建脚本与 SBOM/Notices。
   - 不在内核仓库中放置任何涉及商业机密、私有服务端接口、私有证书或业务凭据的代码。

3. **App 内部合规保留项**：
   - 保持应用内设置页面中关于 `OpenSourceNotices.json` 的开源合规公示及指向公开内核 release 的 Source Offer 链接。

4. **若需实现内核私有化**：
   - 列入未来架构演进专项，按“自研纯宽松许可技术栈”路径推进重写，完成后再切换为纯闭源模式。
