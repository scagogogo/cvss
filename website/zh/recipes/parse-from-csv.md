---
title: 从 CSV 文件批量解析与评分 CVSS 向量
description: 用 cvss csv read 从 CSV 读取 CVSS 向量，再通过管道接入 csv write 或 batch score 给每行评分。
---

# 📑 从 CSV 文件批量解析与评分 CVSS 向量

## 问题

你的漏洞台账在 CSV 里——其中一列是 CVSS 向量串，旁边还有 CVE 编号、日期、负责人——你需要给每行评分，补上基础分和严重性。

## 方案

流程如下：

```mermaid
flowchart LR
  C[📄 vulns.csv<br/>vector in column 0] --> R[📖 csv read<br/>parse column 0]
  R --> P{row valid?}
  P -- yes ✅ --> V[*Cvss3x per row]
  P -- no ❌ + --lax --> E[⚠️ skip + stderr]
  P -- no, strict --> AB[❌ abort whole read]
  V --> W[✍️ csv write → scored CSV]
  V --> J[🔢 batch score → JSON<br/>join via line field]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef data fill:#f9f0ff,stroke:#722ed1,color:#391085
  classDef warn fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class C in
  class R,W step
  class P branch
  class V data
  class J out
  class E,AB warn
```

### 1. CSV 里把向量放在第一列

`csv read` 把每行的**第一列**解析为向量串，并跳过表头行。把向量放第一列：

`vulns.csv`：

```csv
vector,cve
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,CVE-2024-0001
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L,CVE-2024-0002
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L,CVE-2024-0003
```

::: warning 向量必须在第 0 列
`csv read` 只读 `record[0]`。如果 CSV 是 `cve,vector`（CVE 在前），会什么都打不出来——因为 CVE 编号解析不成向量，而表头又吃掉了第一行数据。务必把向量放在第一列。
:::

### 2. 读回并重新输出带分数的 CSV

把 `csv read` 管到 `csv write`。`csv write` 从 stdin 读取向量（每行一个），输出包含全部子分数的完整 CSV：

```bash
cvss csv read vulns.csv | cvss csv write
```

```csv
vector_string,version,base_score,base_severity,temporal_score,temporal_severity,environmental_score,environmental_severity,impact_sub_score,exploitability_sub_score
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,3.1,9.8,Critical,,,,,5.8731,3.8870
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L,3.1,5.3,Medium,,,,,1.4124,3.8870
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L,3.1,3.8,Low,,,,,3.3734,0.3330
```

写到文件用 `-o`：

```bash
cvss csv read vulns.csv | cvss csv write -o scored.csv
```

### 3. 输出 JSON 并把 CVE 编号关联回去

若想保留 CVE 编号与分数，输出 JSON 再做一次关联。`batch score` 也能从 stdin 读向量：

```bash
cvss csv read vulns.csv | cvss batch score - --format json
```

```json
{
  "line": 1,
  "score": 9.8,
  "severity": "Critical",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
{
  "line": 2,
  "score": 5.3,
  "severity": "Medium",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
}
```

`line` 对应 `vulns.csv` 里的行号（减去表头），可以据此把 `line` 关联回原始 CSV 行。

### 4. 容忍脏行

如果有些行向量格式不对，`--lax` 会跳过并在 stderr 报告每行，而不是整批中止：

```bash
cvss csv read --lax messy.csv | cvss csv write
```

## 讨论

- **默认是严格模式。** 不加 `--lax` 时，第一个无效行就会让整个读取失败。不确定的话先对抽出来的向量列跑 `cvss batch validate`。
- **表头识别是启发式的。** `csv read`（lax 模式）把第一行当表头，除非它以 `CVSS:` 开头。`vector,cve` 这种表头能正确跳过；恰好以 `CVSS:` 开头的数据行会被当成数据解析，而不是跳过。
- **其他列会被丢弃。** `csv read` 只输出解析后的向量串，所以 `cve`、`owner` 等列不会随管道传下去。用 `batch score --format json` 的 `line` 字段关联回源行，或者用 `awk`/脚本直接处理 CSV。
- **Go SDK 替代方案。** `cvss.ReadCSV(r)` 返回 `[]*Cvss3x`；`cvss.ReadCSVLax(r)` 返回 `([]*Cvss3x, []CSVReadError, error)`。当你需要进程内拿到解析后的对象而不是带分数的 CSV 时，用它们。

## 另见

- [`csv read`](/zh/cli/commands/csv-read)——本篇用到的读取命令
- [`csv write`](/zh/cli/commands/csv-write)——输出带分数的 CSV
- [`batch score`](/zh/cli/commands/batch-score)——从 stdin 做 JSON 评分
- [筛选 Critical 漏洞](/zh/recipes/filter-critical-vulns)
- [导出 JSON](/zh/recipes/export-to-json)
