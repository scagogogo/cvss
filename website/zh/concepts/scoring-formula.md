---
title: 评分公式
description: CVSS v3.0/v3.1 评分公式 —— Base = roundup(min(ISC+ESC,10))，含 Scope 调整，以及 Temporal、Environmental 扩展，源自 pkg/cvss/calculator.go 与 scores.go。
---

# 🧮 评分公式

## 简介

CVSS 产出三层分数 —— **基础（Base）**、**时间（Temporal）**、**环境（Environmental）** —— 后者是对前者的逐层细化。本页给出 `pkg/cvss/calculator.go` 与 `pkg/cvss/scores.go` 中实现的确切公式，并附完整计算流程图。

## 基础评分

基础评分仅依赖八个基础指标（AV、AC、PR、UI、S、C、I、A）。

### 影响子评分（ISC）

```
ISC_base = 1 - (1 - C) × (1 - I) × (1 - A)
```

Scope 为 **Unchanged** 时：

```
ISC = 6.42 × ISC_base
```

Scope 为 **Changed** 时：

```
ISC = 7.52 × (ISC_base - 0.029) - 3.25 × (ISC_base × 0.9731 - 0.02)^13
```

当 CIA 三项全为 `None`（0）时，`ISC` 强制为 `0`。

### 可利用性子评分（ESC）

```
ESC = 8.22 × AV × AC × PR × UI
```

`PR` **依赖 Scope** —— 同一 `PR` 值在 Scope Changed 与 Unchanged 时分数不同（见 `vector.GetPrivilegesRequiredScore`）。`UI` **依赖版本** —— `UI:R` 在 v3.0 为 `0.56`，在 v3.1 为 `0.62`（见 [v3.0 与 v3.1 差异](./version-diff)）。

### 合成基础评分

```
若 ISC <= 0：  Base = 0
否则若 Scope Changed：
    Base = roundup( min( 1.08 × (ISC + ESC), 10 ) )
否则：
    Base = roundup( min( ISC + ESC, 10 ) )
```

`1.08` 乘子仅在 Scope Changed 时应用，反映跨 Scope 影响的放大效应。

## 时间评分

时间评分用基于时间的因子细化基础评分。未设置的时间指标默认为 `1.0`（即 "Not Defined"）：

```
Temporal = roundup( Base × E × RL × RC )
```

| 因子 | 指标 | 未设置默认值 |
|------|------|-------------|
| `E`  | Exploit Code Maturity（利用代码成熟度） | 1.0 |
| `RL` | Remediation Level（修复级别） | 1.0 |
| `RC` | Report Confidence（报告置信度） | 1.0 |

## 环境评分

环境评分最为细化：它从**修改后的**基础指标（带 `M` 前缀）重新推导 ISC 与 ESC，应用**安全需求**调整因子（CR/IR/AR：L/M/H 对应 `0.5`/`1.0`/`1.5`），再乘以时间因子：

```
MISC = 6.42 × min(MC×CR, 1) ...    （或 Changed 时的 7.52 公式）
MESC = 8.22 × MAV × MAC × MPR × MUI

若 MISC <= 0：  Env = 0
否则若 Modified Scope Changed：
    Env = roundup( min( 1.08 × (MISC + MESC), 10 ) )
否则：
    Env = roundup( min( MISC + MESC, 10 ) )

Environmental = roundup( Env × E × RL × RC )
```

每个 `M*` 指标在取值为 `X`（Not Defined）时回退到对应基础指标。

## 计算流程

```mermaid
flowchart TD
    Start([Cvss3x 向量]) --> Check{Check() 合法?}
    Check -- 否 --> Err([返回 error])
    Check -- 是 --> ISC[calculateImpactSubScore]
    ISC --> ESC[calculateExploitabilitySubScore]
    ESC --> Zero{ISC <= 0?}
    Zero -- 是 --> Base0([Base = 0])
    Zero -- 否 --> Scope{Scope Changed?}
    Scope -- 是 --> BaseChg["roundup(min(1.08×(ISC+ESC),10))"]
    Scope -- 否 --> BaseUn["roundup(min(ISC+ESC,10))"]
    Base0 --> HasT{有时间指标?}
    BaseChg --> HasT
    BaseUn --> HasT
    HasT -- 否 --> HasE{有环境指标?}
    HasT -- 是 --> Temp["calculateTemporalScore<br/>roundup(Base×E×RL×RC)"]
    Temp --> HasE
    HasE -- 否 --> OutBase([返回 Base / Temporal])
    HasE -- 是 --> Env["calculateEnvironmentalScore<br/>MISC + MESC + CR/IR/AR + E×RL×RC"]
    Env --> OutEnv([返回 Environmental])
```

## 代码实现

| 公式片段 | 源码位置 |
|---------|---------|
| `calculateBaseScore` | `pkg/cvss/calculator.go` |
| `calculateImpactSubScore`（ISC） | `pkg/cvss/calculator.go` |
| `calculateExploitabilitySubScore`（ESC） | `pkg/cvss/calculator.go` |
| `calculateTemporalScore` | `pkg/cvss/calculator.go` |
| `calculateEnvironmentalScore` + `calculateModifiedImpactSubScore` | `pkg/cvss/calculator.go` |
| `roundUp`（内部）与公开 `RoundUp` | `pkg/cvss/calculator.go`、`pkg/cvss/scores.go` |
| `GetBaseScore` / `GetTemporalScore` / `GetEnvironmentalScore` | `pkg/cvss/scores.go` |
| `GetImpactSubScore` / `GetExploitabilitySubScore` | `pkg/cvss/scores.go` |
| `GetAllScores`（一次性计算所有层） | `pkg/cvss/scores.go` |

### `roundUp` —— CVSS 整数算法

```go
// pkg/cvss/calculator.go
func roundUp(x float64) float64 {
    intInput := int(math.Round(x * 100000))
    if intInput%10000 == 0 {
        return float64(intInput) / 100000
    }
    return float64(intInput + (10000 - intInput%10000)) / 100000
}
```

`Roundup(x)` 返回大于等于 `x` 的、精确到一位小数的最小数。它以 `cvss.RoundUp` 导出，便于外部代码按同一规则取整。

### 一次性获取所有分数

```go
calc := cvss.NewCalculator(cv)
all, err := calc.GetAllScores()
// all.BaseScore, all.TemporalScore, all.EnvironmentalScore,
// all.BaseSeverity, all.ImpactSubScore, all.ExploitabilitySubScore, ...
```

`AllScores` 还携带 `HasTemporal` / `HasEnvironmental` 标志与三个严重性等级，单趟计算完成，避免重复推导 ISC/ESC。

## 示例

```bash
$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
10.0 (Critical)

$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
9.8 (Critical)

$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
6.5 (Medium)
```

第一个向量 Scope 为 Changed（`S:C`），故应用 `1.08` 乘子；第二个除 Scope 为 Unchanged 外完全相同，分数从 `10.0` 降到 `9.8`。

## 相关

- [严重性等级](./severity) —— 应用于此处产出分数的阈值
- [v3.0 与 v3.1 差异](./version-diff) —— `UI:R` 与 `roundUp` 的版本分支
- [Go SDK：calculator](/zh/sdk/calculator) —— 面向 SDK 的评分 API
