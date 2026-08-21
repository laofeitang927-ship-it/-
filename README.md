# PRWI v0.1.2-r2 Candidate r6 独立复验（GitHub Actions）

本仓库只用于独立托管环境 fresh-extract replay，不修改候选 ZIP 内的任何 bytes。

## 本轮为什么是 r6

Run #5 的两条 Linux fresh-extract replay 已分别完成 19/19 mutation、C01 和完整工作目录归档；A 用时约 4 小时 13 分，B 用时约 3 小时 10 分。最终红灯发生在 40 秒的 receipts/hash 汇总结论层：旧 wrapper 对四个预执行阻断案例使用了不完整的身份闭合，导致 replay 结果虽然完成，候选仍按 fail-closed 判定为 `NO`。

r6 只修复交付和核验层，不改冻结 source/core bytes：

- 四个预执行阻断案例必须从同级 `receipt.yaml` 恢复真实 workflow run ID，并与 mutation row、gate、计数器和错误层未修改证明逐项匹配；不再接受合成身份。
- 每次 replay 必须闭合为 19 个结果、15 个原始 result ID、19 个权威身份、4 个已验证停点和 14 份 current-run audit receipts。
- wrapper 与独立 postcheck 必须对身份 inventory、receipt exact-byte hash 和 canonical semantic projection 得到一致结论。
- ZIP 使用唯一 r6 顶层目录、固定排序/时间戳/权限，并核验 UTF-8 EFS、清单、大小、逐文件 SHA-256、baseline manifest 及 source/frozen/semantic 固定闭包。
- 运行环境固定为 CPython `3.13.12`、`PyYAML==6.0.3`、`pypdf==6.14.2`；任一依赖缺失均 fail-closed。

## 你只需要做什么

1. 在 GitHub Desktop 中提交本次改动，Summary 可填：`Add r6 receipt-backed revalidation candidate`。
2. 点击 **Push origin**。
3. 打开仓库 **Actions** 页，选择 **PRWI R2 independent fresh-extract revalidation**。
4. 点击 **Run workflow**，再点击绿色的 **Run workflow**。
5. 等待运行结束，不要中途取消。按 Run #5 实测，通常约 4 小时 15 分；两个 replay 并行，各自 `workers=1`，较慢的一条决定总时长。
6. 无论绿灯或红灯，都打开该次运行，在页面底部下载名称以 `prwi-r2-independent-revalidation-` 开头的 artifact。

## 输入字节身份

工作流只接受：

```text
input/production-research-workflow-integration-v0.1.2-r2-external-revalidation-bundle-final-candidate-r6.zip
SHA-256 = 1186a1385328a67b443cc7d86bc210873ffa145c7ae0dd2ca53f853544715227
```

任何 ZIP、路径、manifest、source/frozen byte 或 semantic contract 不一致都会在长跑前或最终结论中 fail-closed。

## 看哪个结果

解压最终 artifact，首先打开：

`independent-external-revalidation-result.yaml`

只有同时出现下面两项，才代表这次独立复验通过：

```text
decision: PASS
OPTIMIZED_R2_CANDIDATE_READY: 'YES'
```

红灯时仍应下载 artifact；其中 `failures`、完整 diagnostics、receipts、run-scoped hashes、canonical semantic projection 和 A/B cross-run hash 会保留具体原因。

## 工作流实际做什么

- 校验 r6 ZIP 的固定 SHA-256 和确定性 archive envelope。
- 在两个独立 `ubuntu-latest` runner 上分别 fresh extract；两个 runner 并行，但每个 runner 严格 `workers=1`。
- 每条 replay 的 child timeout 为 `18000` 秒，GitHub job 上限为 `355` 分钟。
- 独立核验每次 19/19 mutation、C01 六个 gate 与六类对象证据。
- 核验四个 receipt-backed 预执行停点、15 个原始 ID、19 个权威身份、14 份 current-run receipts，拒绝重复或合成身份。
- 重算 receipt exact-byte SHA-256、audited-script hashes、executable probes、canonical semantic hash，并核验 A/B semantic hash stability。
- 无论 PASS、FAIL 或 timeout，均上传两份完整 workdir 归档和最终 diagnostics/hashes。

## 当前仍未放行

在新的 r6 GitHub Actions 运行产生合格 PASS 之前，状态保持：

```text
OPTIMIZED_R2_CANDIDATE_READY = NO
CURRENT_R1_EXTERNAL_REVALIDATION = FAIL
CURRENT_R2_EXTERNAL_REVALIDATION = PASS
INDEPENDENT_EXTERNAL_REVALIDATION_REQUIRED = YES
FIXTURE2_ALLOWED_TO_START = NO
LEARNING_COMPILE_PRODUCTION_INTEGRATION_ALLOWED = NO
FROZEN_CORE_REOPEN_REQUIRED = NO
```

即使 r6 独立复验 PASS，也不会自动授权 Fixture 2 或 learning compile production integration；两者仍需后续单独决定。
