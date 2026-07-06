<div align="center">

# CVSS Skills

**专业 CVSS v3.0 / v3.1 工具包 — 解析、评分、验证、比较与构建漏洞向量**

[![CI](https://github.com/scagogogo/cvss-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/scagogogo/cvss-skills/actions/workflows/ci.yml)
[![Release](https://github.com/scagogogo/cvss-skills/actions/workflows/release.yml/badge.svg)](https://github.com/scagogogo/cvss-skills/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss-skills)](https://goreportcard.com/report/github.com/scagogogo/cvss-skills)
[![codecov](https://codecov.io/gh/scagogogo/cvss-skills/graph/badge.svg?token=CVSSSKILLS)](https://codecov.io/gh/scagogogo/cvss-skills)
[![Coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/scagogogo/cvss-skills/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Release](https://img.shields.io/github/v/release/scagogogo/cvss-skills)](https://github.com/scagogogo/cvss-skills/releases/latest)

**🌐 网站**: [scagogogo.github.io/cvss-skills](https://scagogogo.github.io/cvss-skills/) — 完整文档、教程、API 参考

**Languages**: [English](README.md) | 简体中文

</div>

> **面向 AI 智能体**：本 README 按机器可读方式组织。安装命令见 [Integration Methods](#-概述)，命令清单见 [CLI Commands](#-cli-命令)，各系统/架构的精确下载 URL 见 [Pre-built Binaries](#-预编译二进制)。官网 <https://scagogogo.github.io/cvss-skills/> 内容同步。

---

## 🤖 概述

**CVSS Skills** 是一个经过充分测试的通用漏洞评分系统（CVSS）v3.0 / v3.1 工具包。它解决了以编程方式处理 CVSS 向量时那些令人头疼的环节：易错的解析、版本相关的评分公式、手工比较以及零散的验证。

它通过 **4 种集成方式**交付：

```mermaid
flowchart LR
    subgraph Methods["Integration Methods"]
        direction TB
        S["🤖 Skills<br/>Claude Code"]
        SDK["📦 Go SDK<br/>go get"]
        CLI["💻 CLI<br/>pre-built"]
        MCP["🔌 MCP Server<br/>AI agents"]
    end

    S -->|natural language| U(["User"])
    SDK -->|library| A(["App"])
    CLI -->|scripts| B(["Batch"])
    MCP -->|protocol| C(["Agent"])

    classDef m fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef u fill:#f6ffed,stroke:#52c41a,color:#135200
    class S,SDK,CLI,MCP m
    class U,A,B,C u
```

| | 集成方式 | 适用场景 | 安装 |
|---|---|---|---|
| 🤖 | **Skills**（Claude Code） | 交互式分析、自然语言 | `claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills` |
| 📦 | **Go SDK** | 用 Go 构建安全工具 | `go get github.com/scagogogo/cvss-skills@latest` |
| 💻 | **CLI** | 脚本化、批量处理 | 见 [Pre-built Binaries](#-预编译二进制) |
| 🔌 | **MCP** | AI 智能体集成 | 将本仓库添加为 MCP 服务器 |

**仓库信息**

| | |
|---|---|
| 模块路径 | `github.com/scagogogo/cvss-skills` |
| 语言 | Go（≥ 1.18） |
| 许可证 | MIT |
| CLI 二进制名 | `cvss` |
| CLI 入口 | `cmd/cvss-cli/` |
| 发布产物 | 30+ 个包（6 系统 × 多架构），经 [GoReleaser](.goreleaser.yml) 构建 |
| 最新版本 | [![GitHub Release](https://img.shields.io/github/v/release/scagogogo/cvss-skills)](https://github.com/scagogogo/cvss-skills/releases/latest) |
| 官网 | <https://scagogogo.github.io/cvss-skills/> |

---

## 🏛️ 架构

每个集成层都是同一套经过充分测试的 Go 核心之上的薄封装 —— 评分逻辑没有任何重复实现：

```mermaid
flowchart TB
    subgraph Surfaces["Integration Surfaces"]
        direction LR
        Skills["🤖 Claude Code Skills"]
        MCP["🔌 MCP Server"]
        CLI["💻 CLI (cvss)"]
        SDK["📦 Go SDK"]
    end
    subgraph Core["Core Packages"]
        direction LR
        Parser["pkg/parser"]
        CVSS["pkg/cvss"]
        Vector["pkg/vector"]
    end
    Skills --> CLI
    MCP --> CLI
    CLI --> Parser
    SDK --> Parser --> Vector --> CVSS --> Result(["Score · Severity · JSON"])
```

标准流水线 —— 从原始向量字符串到评分与严重性：

```mermaid
flowchart LR
    A["CVSS:3.1/AV:N/..."] --> B{Parse}
    B -->|error| E1["error<br/>(invalid magic head,<br/>malformed vector, …)"]
    B -->|ok| C["Cvss3x struct"]
    C --> D{Validate}
    D -->|missing metric| E2["ValidationErrors"]
    D -->|complete| F["Calculator"]
    F --> G["Overall score<br/>(base / temporal /<br/>environmental, as present)"]
    G --> H["GetSeverity()"]
    H --> K(["9.8 · Critical"])
```

## ✨ 功能全景图

```mermaid
mindmap
  root((CVSS Skills))
    Parsing
      v3.0 / v3.1 vectors
      Relaxed parsing
      ParseAndScore
      Builder API
      FromMap
    Scoring
      Base / Temporal / Environmental
      Severity ratings
      Per-metric breakdown
    Validation
      Structural checks
      ValidationErrors
      IsComplete
      MissingMetrics
    Comparison
      Diff
      Merge
      Equal / SameSeverity
    Distance
      Euclidean
      Manhattan
      Hamming
      Jaccard
    Serialization
      JSON
      Text
      CSV I/O
      Batch
    Advanced
      Sensitivity analysis
      Score range
      Version-aware
      Presets
      Mock generators
```

| 类别 | 功能 |
|------|------|
| **解析** | 解析 v3.0/v3.1 向量、宽松解析（无需 `CVSS:` 前缀）、`ParseAndScore` 一步到位、Builder API、`FromMap` |
| **评分** | 基础 / 时间 / 环境评分、严重性评级、逐指标评分分解 |
| **验证** | 结构化验证、`ValidationErrors` 逐指标报错、`IsComplete()`、`MissingMetrics()` |
| **比较** | Diff（逐指标对比）、Merge、Equal / SameSeverity 判等 |
| **距离** | 欧氏距离、曼哈顿距离、汉明距离、Jaccard 相似度 — 含环境感知变体 |
| **序列化** | JSON 序列化/反序列化、文本序列化/反序列化、CSV 读写、批量处理 |
| **高级** | 敏感度分析、部分向量评分范围、版本感知评分、预设向量、Mock 数据生成器 |

---

## 🚀 快速开始

### 1. Skills（Claude Code）— 一行命令

```bash
claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills
```

启用 **9 个 CVSS 技能** —— 每个是 `.claude/skills/` 下的一个 markdown 指导文件，告诉 Claude 应运行哪条 `cvss` CLI 命令：`cvss-parse`、`cvss-score`、`cvss-validate`、`cvss-construct`、`cvss-compare`、`cvss-metrics`、`cvss-serialize`、`cvss-advanced`、`cvss-install`。用自然语言提问（如「score this vector: …」），Claude 会自动选用正确的技能。

<details>
<summary>手动安装</summary>

添加到项目的 `.claude/settings.json` 或 `~/.claude/settings.json`：

```json
{
  "mcpServers": {
    "cvss-skills": {
      "type": "github",
      "url": "https://github.com/scagogogo/cvss-skills"
    }
  }
}
```

</details>

### 2. Go SDK — 功能完整的库

```bash
go get github.com/scagogogo/cvss-skills@latest
```

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // One-step parse and score
    cv, score, severity, err := parser.ParseAndScore(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Score: %.1f (%s)\n", score, severity) // Score: 9.8 (Critical)
    _ = cv
}
```

### 3. CLI — 预编译二进制或 `go install`

```bash
# Install a pre-built binary (auto-detects OS/arch, resolves latest version)
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
case "$arch" in arm64) arch=aarch64 ;; amd64) arch=x86_64 ;; esac
ver=$(curl -sL https://api.github.com/repos/scagogogo/cvss-skills/releases/latest | sed -nE 's/.*"tag_name":\s*"v?([^"]+)".*/\1/p')
curl -sL "https://github.com/scagogogo/cvss-skills/releases/download/v${ver}/cvss-skills_${ver}_${os}_${arch}.tar.gz" | tar xz
sudo mv cvss /usr/local/bin/

# Or install with Go
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest

# Use
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```

### 4. MCP — AI 智能体集成

从任何兼容 MCP 的客户端连接此仓库作为 MCP 服务器，即可通过标准模型上下文协议使用 CVSS 工具。

---

## 📦 预编译二进制

每次 [发布](https://github.com/scagogogo/cvss-skills/releases/latest) 附带 **30+ 个包**，由 GoReleaser 经 GitHub Actions 构建。归档命名：

```
cvss-skills_<version>_<os>_<arch>[v<arm>].<tar.gz|zip>
```

**URL 模板**（替换 `<version>`，如 `0.1.0`）：

```
https://github.com/scagogogo/cvss-skills/releases/download/v<version>/cvss-skills_<version>_<os>_<arch>.<ext>
```

| 系统 | 架构 |
|---|---|
| **linux** | `x86_64`, `aarch64`, `i386`, `armv5`, `armv6`, `armv7`, `ppc64le`, `s390x`, `riscv64`, `mips64le` |
| **darwin** | `x86_64`, `aarch64` |
| **windows** | `x86_64`, `aarch64`, `i386`（`.zip`） |
| **freebsd** | `x86_64`, `aarch64`, `i386`, `armv5`, `armv6`, `armv7` |
| **netbsd** | `x86_64`, `aarch64`, `i386`, `armv5`, `armv6`, `armv7` |
| **openbsd** | `x86_64`, `aarch64`, `i386`, `armv5`, `armv6`, `armv7` |

每次发布还附带 `checksums.txt`（SHA256）。完整矩阵与校验步骤见[下载页](https://scagogogo.github.io/cvss-skills/downloads/)。

<details>
<summary>从源码构建</summary>

```bash
git clone https://github.com/scagogogo/cvss-skills.git
cd cvss-skills
go build -o cvss ./cmd/cvss-cli/
# or: make build
```

</details>

---

## 🧮 CVSS 向量结构

CVSS 向量由最多 **3 层**指标组成：

```mermaid
flowchart LR
    Prefix["CVSS:3.1<br/>version prefix"] --> Base

    subgraph Base["Base — required (8 metrics)"]
        direction LR
        AV["AV<br/>Attack Vector"]
        AC["AC<br/>Complexity"]
        PR["PR<br/>Privileges"]
        UI["UI<br/>User Inter."]
        S["S<br/>Scope"]
        C["C<br/>Confidential."]
        I["I<br/>Integrity"]
        A["A<br/>Availability"]
    end

    subgraph Temporal["Temporal — optional"]
        direction LR
        E["E<br/>Exploit"]
        RL["RL<br/>Remediation"]
        RC["RC<br/>Report Conf."]
    end

    subgraph Env["Environmental — optional"]
        direction LR
        CR["CR/IR/AR<br/>Requirements"]
        M["MAV…MA<br/>Modified base"]
    end

    Base --> Temporal --> Env

    classDef base fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef temp fill:#fffbe6,stroke:#faad14,color:#874d00
    classDef env fill:#f9f0ff,stroke:#722ed1,color:#391085
    class AV,AC,PR,UI,S,C,I,A base
    class E,RL,RC temp
    class CR,M env
```

| 层级 | 指标 | 是否必需 |
|------|------|----------|
| **基础** | AV, AC, PR, UI, S, C, I, A | 是（全部 8 个） |
| **时间** | E, RL, RC | 否 |
| **环境** | CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA | 否 |

---

## 🎚️ 严重性等级

| 等级 | 分数范围 | 颜色 |
|------|---------|------|
| 无 | 0.0 | 灰色 |
| 低 | 0.1 – 3.9 | 绿色 |
| 中 | 4.0 – 6.9 | 黄色 |
| 高 | 7.0 – 8.9 | 橙色 |
| 严重 | 9.0 – 10.0 | 红色 |

```mermaid
flowchart LR
    Score(["Base Score 0.0–10.0"]) --> D{Band?}
    D -->|"= 0.0"| N["None"]
    D -->|"0.1–3.9"| L["Low"]
    D -->|"4.0–6.9"| M["Medium"]
    D -->|"7.0–8.9"| H["High"]
    D -->|"9.0–10.0"| Cr["Critical"]

    classDef none fill:#f0f0f0,stroke:#8c8c8c,color:#262626
    classDef low fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef med fill:#fffbe6,stroke:#faad14,color:#874d00
    classDef high fill:#fff7e6,stroke:#fa8c16,color:#873800
    classDef crit fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    class N none
    class L low
    class M med
    class H high
    class Cr crit
```

---

## 📚 Go SDK 示例

### 解析和计算

```go
cvssVector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatalf("Parse failed: %v", err)
}

calculator := cvss.NewCalculator(cvssVector)
score, _ := calculator.Calculate()
fmt.Printf("CVSS Score: %.1f\n", score)              // 9.8
fmt.Printf("Severity: %s\n", cvss.GetSeverity(score)) // Critical
```

### Builder API

```go
cv := cvss.NewBuilder().Version(3, 1).
    AV('N').AC('L').PR('N').UI('N').S('U').
    C('H').I('H').A('H').MustBuild()

score, _ := cvss.NewCalculator(cv).Calculate()
fmt.Printf("Score: %.1f\n", score) // 9.8
```

### 结构化验证

```go
err := cv.Validate()
if ve, ok := err.(cvss.ValidationErrors); ok {
    fmt.Printf("Missing: %v\n", ve.MissingMetrics())
}
```

### 差异和合并

```go
diffs := cv1.Diff(cv2)
for _, d := range diffs {
    fmt.Printf("%s: %s vs %s\n", d.Metric, d.V1, d.V2)
}

merged := cv1.Merge(cv2WithTemporal)
```

### 距离计算

```go
dc := cvss.NewDistanceCalculator(cv1, cv2)
fmt.Printf("Euclidean: %.2f\n", dc.EuclideanDistance())
fmt.Printf("Manhattan: %.2f\n", dc.ManhattanDistance())
fmt.Printf("Jaccard: %.2f\n", dc.JaccardSimilarity())
```

### 评分分解

```go
calc := cvss.NewCalculator(cv)
breakdown, _ := calc.GetScoreBreakdown()
for _, m := range breakdown.AllMetrics() {
    fmt.Printf("%s:%s = %.2f\n", m.ShortName, m.Value, m.Score)
}
```

### 便捷方法

```go
cv.IsComplete()         // true if all 8 base metrics set
cv.Is31()               // true if CVSS v3.1
cv.HasTemporalMetrics() // true if temporal metrics present
cv.HasEnvironmentalMetrics() // true if environmental metrics present
cv.MissingMetrics()     // list of missing metric names
cv.Clone()              // deep copy
cv.BaseOnly()           // clone without temporal/environmental
cv.Equal(other)         // exact metric comparison
cv.EqualScore(other)    // score-based comparison
cv.SameSeverity(other)  // severity-based comparison
```

---

## 💻 CLI 命令

30+ 条命令。所有命令均支持 `--format json` 输出结构化数据。运行 `cvss --help` 查看完整列表。

| 命令 | 说明 | 示例 |
|------|------|------|
| `cvss score` | 计算 CVSS 评分 | `cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss parse` | 解析向量字符串 | `cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss validate` | 验证向量字符串 | `cvss validate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `cvss build` | 通过指标标志构建向量 | `cvss build --AV N --AC L --PR N --UI N --S U --C H --I H --A H` |
| `cvss describe` | 人类可读的描述 | `cvss describe "CVSS:3.1/..."` |
| `cvss diff` | 比较两个向量 | `cvss diff "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss merge` | 合并两个向量 | `cvss merge "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss distance` | 计算距离度量 | `cvss distance "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss analyze` | 影响/敏感度分析 | `cvss analyze "CVSS:3.1/..."` |
| `cvss range` | 部分向量的评分范围 | `cvss range "CVSS:3.1/AV:N"` |
| `cvss preset` | 生成预设向量 | `cvss preset critical` |
| `cvss random` | 生成随机向量 | `cvss random --cvss-version 3.1` |
| `cvss json` | JSON 序列化 | `cvss json "CVSS:3.1/..."` |
| `cvss csv` | CSV 读写（子命令） | `cvss csv read input.csv` |
| `cvss batch` | 批量评分/校验（子命令） | `cvss batch score vectors.txt` |
| `cvss severity` | 由分数得严重性等级 | `cvss severity 9.8` |
| `cvss sort` | 按评分排序向量 | `cvss sort vectors.txt` |
| `cvss canonicalize` | 规范化向量格式 | `cvss canonicalize "CVSS:3.1/..."` |
| `cvss convert` | 版本转换 | `cvss convert "CVSS:3.0/..." --to 3.1` |
| `cvss enumerate` | 列出某指标的合法取值 | `cvss enumerate --metric AV` |
| `cvss equal` | 比较两个向量 | `cvss equal "CVSS:3.1/..." "CVSS:3.1/..."` |
| `cvss get` | 获取单个指标值 | `cvss get "CVSS:3.1/..." AV` |
| `cvss groups` | 按分组显示指标 | `cvss groups "CVSS:3.1/..."` |
| `cvss map` | 输出向量为 key=value | `cvss map "CVSS:3.1/..."` |
| `cvss modify` | 修改指标（用标志） | `cvss modify "CVSS:3.1/..." --AV L` |
| `cvss base-only` | 移除时间/环境指标（别名 `strip`） | `cvss base-only "CVSS:3.1/..."` |
| `cvss subs` | 显示影响/可利用子分数 | `cvss subs "CVSS:3.1/..."` |

---

## 📖 文档

官网：**<https://scagogogo.github.io/cvss-skills/>**

- [集成方式](https://scagogogo.github.io/cvss-skills/integration/) — 对比 4 种使用 CVSS Skills 的方式
- [CLI 参考](https://scagogogo.github.io/cvss-skills/cli/) — 全部 30+ 命令
- [下载](https://scagogogo.github.io/cvss-skills/downloads/) — 预编译二进制矩阵
- [API 参考](https://scagogogo.github.io/cvss-skills/docs/api/) — 完整的 Go SDK API 文档
- [示例和教程](https://scagogogo.github.io/cvss-skills/docs/examples/) — 实用的使用示例
- [快速开始指南](https://scagogogo.github.io/cvss-skills/docs/api/getting-started) — 5 分钟快速上手
- [中文文档](https://scagogogo.github.io/cvss-skills/zh/) — 简体中文

---

## 🤝 贡献

欢迎贡献代码、报告问题和提出建议！

- [GitHub Issues](https://github.com/scagogogo/cvss-skills/issues) — 报告问题或建议
- [贡献指南](https://scagogogo.github.io/cvss-skills/docs/CONTRIBUTING) — 了解如何贡献代码

## License

MIT 许可证 — 详见 [LICENSE](LICENSE) 文件。

## Acknowledgments

- [CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v3.0 规范](https://www.first.org/cvss/v3.0/specification-document)
