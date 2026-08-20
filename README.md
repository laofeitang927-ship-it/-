# PRWI v0.1.2-r2 Candidate r5 独立复验（GitHub Actions，依赖修正版 v3）

本仓库只用于一次独立托管环境复验，不修改候选 ZIP 内的任何 bytes。

## 为什么需要 v3

2026-08-20 的首次 Ubuntu 执行给出 fail-closed 结果：Run A 为 8/19，11 项失败，冻结 IR Validator 对 C01 候选 IR 报告 39 个 blocker。独立诊断确认该次 GitHub 环境只安装了 PyYAML，而冻结编译器读取 PDF 还需要 `pypdf`；缺少该依赖时 PDF 文本读取被降级为空，因而 11 份 Evidence 的 `facts` 为空并触发连锁失败。

v3 不修改 r5 候选 ZIP 的任何 bytes，只在外部执行环境中固定安装 `PyYAML==6.0.3` 和 `pypdf==6.14.2`，然后重新执行两次独立 fresh-extract replay。r5 在本次新运行真正 PASS 前仍不可放行。

## 你只需要做什么

1. 在 GitHub 新建一个 **Private** 仓库。
2. 把本交付目录中的全部内容原样放入仓库；必须保留 `.github/workflows/`、`input/` 和 `tools/` 三个目录。
3. 打开仓库的 **Actions** 页。
4. 左侧选择 **PRWI R2 independent fresh-extract revalidation**。
5. 点击 **Run workflow**，再点击绿色的 **Run workflow**。
6. 等待任务结束；不要中途取消。正常情况下可能持续较久。
7. 打开该次运行，在页面底部下载名称以 `prwi-r2-independent-revalidation-` 开头的 artifact。

## 看哪个结果

解压 artifact 后，首先打开：

`independent-external-revalidation-result.yaml`

只有同时出现下面两行，才代表本次独立复验通过：

```text
decision: PASS
OPTIMIZED_R2_CANDIDATE_READY: 'YES'
```

如果任务显示红色，仍应下载 artifact。红色表示 fail-closed；结果文件里的 `failures` 会说明原因。

## 这个工作流实际做什么

- 校验输入 ZIP SHA-256 必须为 `40a614b2eb09720ab0314b3c4abb35af49636e68d7aba7dcc0e9de62ed8eafe4`。
- 使用标准 `ubuntu-latest` 全新托管 VM，而不是 `ubuntu-slim`。
- 使用 CPython `3.13.12`、`PyYAML==6.0.3` 和 `pypdf==6.14.2`，并把三者版本写入环境证据。
- 串行执行两次独立 fresh extract replay；每次 `workers=1`，child timeout 为 `3600` 秒。
- 独立核验每次 mutation 19/19、C01 六个 gate 和六类对象证据。
- 对四个预执行 fail-closed case 使用明确的 `PREEXECUTION_STOP` case identity；其余 15 个真实执行 case 核验 execution id，并要求 14 份应有的 current-run audit receipts。
- 独立筛选 current-run audit receipts，重算每份 exact-byte SHA-256，并与 wrapper 记录比对。
- 核验 receipt execution identity、五项 leakage counts、audited-script hashes 和 executable probes。
- 按 `canonical-semantic-hash-contract.yaml` 的字段与归一化规则生成 canonical semantic projection，并比较 A/B 两次运行的 semantic hash stability。
- 无论 PASS、FAIL 或内部 3600 秒 timeout，Run B 都会继续执行。
- A/B 完整工作目录分别归档为 `run-a/full-workdir.tar.gz` 与 `run-b/full-workdir.tar.gz`，再连同精选 receipts、结果和最终 `SHA256SUMS` 一起上传，最后才令任务 fail-closed。

## 仍然不自动放开的边界

即使本次结果为 PASS，工作流仍保持：

```text
CURRENT_R1_EXTERNAL_REVALIDATION = FAIL
CURRENT_R2_EXTERNAL_REVALIDATION = PASS
FIXTURE2_ALLOWED_TO_START = NO
LEARNING_COMPILE_PRODUCTION_INTEGRATION_ALLOWED = NO
FROZEN_CORE_REOPEN_REQUIRED = NO
```

Fixture 2 或 learning compile production integration 需要后续单独授权，不能由本次 replay 自动放开。
