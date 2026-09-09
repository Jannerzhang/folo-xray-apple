# Folo Rust 内核私有化/闭源可行性与合规审核报告（内核侧）

> 审核日期：2026-09-10（Asia/Shanghai）  
> 审核对象：`/Users/barneszhang/Documents/UGit/folo-xray-rust-eval/core`，仓库 `Jannerzhang/folo-xray-apple`。  
> 联合审核报告： [iOS 客户端与内核完整报告](https://github.com/Jannerzhang/folo-ios/blob/codex/closed-source-audit-20260910-v2/Docs/PROJECT_CLOSED_SOURCE_AND_LICENSE_AUDIT_REPORT_V2.md)。  
> 本文是工程与许可证风险审查，不替代律师、版权持有人或 Apple 出口合规顾问的书面意见。

## 1. 结论

当前 Rust/Xray 内核不能在继续向 App 用户分发现有二进制的同时直接改成全私有、全闭源。`xray-rust-eval` 的 workspace license 是 MPL-2.0，仓库也明确要求保留上游许可证、锁定依赖，并让客户端 release 指向匹配的公共 source tag、SBOM、notice 和 source lock。

可行的当前模式是：

```text
私有 iOS Swift 客户端 + 公共、可验证的 MPL Rust/Xray 内核
```

如果必须让内核也不公开，必须停止分发 MPL 覆盖代码，或完成可证明的 clean-room 替换/重写并重新完成全部依赖、版权、数据和出口合规审查。仅把 GitHub 仓库设为 Private 不会消除已经分发二进制对应的源码和通知义务。

## 2. 审核快照和证据

- 当前 checkout：`audit/closed-source-feasibility-assessment`，HEAD `a890029434f0d5ddd80b9bb17cdceab76116fa92`。
- 内核代码父提交：`cce3b8c35eb1575a4775c8c03894c324e9c36542`，tag `rust1.3`。
- 上游来源由 `xray-rust-eval/Cargo.toml:18-24` 声明为 MPL-2.0，并指向 `https://github.com/aimalygin/xray-rust`。
- `xray-rust-eval/LICENSE` 保留 MPL-2.0；`LICENSING.md:3-16` 明确写明没有 repository-wide license override，并拒绝 GPL/AGPL/LGPL/SSPL/BUSL、未知和非商业许可。
- `REPOSITORY_BOUNDARIES.md` 与 `compliance/xray-rust-eval-source-lock.yml` 将 MPL 覆盖代码及修改放在公共 source-offer 范围。

MPL-2.0 允许非覆盖代码组成按专有条款分发的 Larger Work，但不允许把覆盖文件及其修改重新标成 Folo Proprietary。若把当前 core 改私有，必须仍然为已分发版本提供接收者可获取的覆盖源码、版权/许可证声明和修改信息；当前项目采用公共 GitHub tag/release 作为履约载体。

## 3. 当前阻塞项

### K-01 / P0：发布 provenance 不是 release-ready

`compliance/xray-rust-artifact-manifest-v1.yml:3-23` 当前为：

```text
status: CANDIDATE_ONLY
releaseReady: false
appIntegrationAllowed: false
artifact.present: false
artifact.signed: false
artifact.linked: false
```

同时该 manifest 的 source repository 是占位的 `https://github.com/Jannerzhang/folo-xray-apple-core`，而实际公共仓库是 `https://github.com/Jannerzhang/folo-xray-apple`。`compliance/xray-rust-eval-source-lock.yml:7-11` 仍锁定旧提交 `e6e8103...`，而当前代码父提交为 `cce3b8c...`。

本次执行结果：

```text
ruby scripts/verify_xray_rust_source_lock.rb
  FAIL: core commit cce3b8c... != e6e8103...
ruby scripts/check_xray_rust_license_audit.rb
  FAIL: metadata hash differs from SBOM
ruby scripts/check_rust_core_boundary.rb
  FAIL: retired path still exists: xray-rust-mobile-eval
```

最后一项是当前 checkout 中的被忽略/生成目录，不是 `git ls-files` 中的已跟踪源代码；但发布前仍须清理它，因为边界 gate 会把它纳入检查。

### K-02 / P1：实际依赖闭包尚未形成可审计的 target-scoped 证据

完整 Cargo metadata 发现以下条件许可证表达式：

```text
r-efi 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later
r-efi 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later
```

检查 iOS arm64 的 `xray-ffi` target tree 时没有发现 `r-efi`，所以它可能属于非 iOS target 的条件依赖；这需要 target-scoped SBOM 和明确排除证据。现有许可证审计正则没有正确处理“表达式以 MIT 开头但含 LGPL 备选”的情况。`xray-rust-eval/website/package-lock.json` 还包含 LGPL 依赖，必须与 Apple artifact 的构建和发布范围明确隔离。

此外，本仓库没有发现能替代 example fixture 的实际 `dependency-approval.yml`。因此即使 iOS 的示例策略 gate 通过，也不能证明最终 XCFramework 的完整依赖闭包已经由版权、许可证和安全负责人批准。

### K-03 / P1：生成物和源代码边界需要清理

当前 checkout 存在被忽略的 `xray-rust-mobile-eval`，内含 `.build`、`Artifacts/XrayRust.xcframework`、`dist` 和 `release` 目录。它们未被 Git 跟踪，但会触发 `check_rust_core_boundary.rb`。发布工作区应只包含可复核源代码、构建脚本和已绑定的 release 输入；生成的 XCFramework 应通过受控 release artifact 进入客户端，不应依赖工作区残留物。

### K-04 / P1：远端仓库存在尚未分诊的依赖安全告警

本次推送该审计分支时，GitHub remote 返回默认分支存在 96 个 Dependabot 漏洞告警（27 critical、18 high、39 moderate、12 low）。这只是仓库级告警，不能直接推导为全部进入 iOS XCFramework；但在没有按最终 iOS target、website、测试和 build-only 依赖拆分的 SBOM、修复记录或书面豁免前，内核依赖安全风险不能视为关闭。

## 4. Apple 关系和建议

Apple 不要求 App 或其源码公开；但 [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) 要求开发者拥有/获准使用包含的知识产权，并禁止不符合平台规则的代码下载执行方式。当前内核可在构建时嵌入私有 App 的 Packet Tunnel，但不能把运行时下载可执行代码作为规避 source offer 的手段。

当前内核包含 TLS/Reality/VLESS 相关加密能力。最终签名 App 仍须依据 Apple 的 [encryption export guidance](https://developer.apple.com/documentation/Security/complying-with-encryption-export-regulations?changes=_7__7&language=objc) 和 [export-compliance workflow](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance) 重新分类；历史审核通过不能代替此次分类。

## 5. 整改顺序

1. 暂不将当前 `folo-xray-apple` 设为 Private，不删除已发布版本的公共 source offer、MPL notices、SBOM 和 source lock。
2. 选定唯一不可变 core tag，修正 source repository URL，重新生成 source lock、Cargo metadata/SBOM、notice、artifact manifest 和 release manifest。
3. 在 macOS 上构建、签名并发布与该 tag 一一对应的 XCFramework；用客户端流水线验证 artifact、source、SBOM、notice 和 ABI hash。
4. 建立真实依赖审批记录，修复许可证表达式解析，明确 iOS target、website、测试、Go oracle 和 build-only 依赖边界。
5. 清理 `xray-rust-mobile-eval` 及其他生成目录，并让 boundary gate 在干净 checkout 中通过。
6. 对 Dependabot 告警按最终 Apple artifact 的 target-scoped SBOM 分诊，修复可达漏洞并记录不能升级的理由和缓解措施。
7. 若目标仍是内核完全闭源，另行启动 clean-room/rewrite 或取得所有必要版权持有人的商业再许可；在此之前不得把当前 MPL 内核改标为 Proprietary。

## 6. 最终判定

**当前内核：不能直接全闭源。**  
**当前推荐：内核保持公共且可验证，客户端单独私有闭源。**  
**未来全闭源：只有在移除/替换 MPL 覆盖代码或取得充分书面授权，并通过新的发布、依赖、版权、出口和真机验证后才可评估。**
