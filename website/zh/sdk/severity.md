---
title: 严重性
description: cvss.Severity 类型、SeverityNone/Low/Medium/High/Critical 常量、GetSeverity/ParseSeverity 及 IsNone/IsLow/IsMedium/IsHigh/IsCritical 方法。
---

# 🏷️ 严重性

🏷️ 功能点 · `pkg/cvss`

`Severity` 是 CVSS 分数映射到的字符串型等级。`GetSeverity` 将 `float64` 分数映射到桶；`ParseSeverity` 将字符串解析为该类型；`Is*` 方法让桶判断读起来像英语。阈值遵循 CVSS v3.1 规范。

## 简介

```go
sev := cvss.GetSeverity(7.5)              // High
sev, _ := cvss.ParseSeverity("critical") // SeverityCritical
fmt.Println(sev.IsHigh())                 // false
```

## 工作原理

`GetSeverity` 应用 CVSS v3.1 阈值阶梯（None=0，Low 0.1–3.9，Medium 4.0–6.9，High 7.0–8.9，Critical 9.0–10.0）。`ParseSeverity` 对五个名称大小写不敏感，`Is*` 方法是对常量的直接相等检查。

```mermaid
flowchart LR
    Score[🔢 float64 score] --> G{🟡 GetSeverity}
    G -- "<= 0" --> None[⚪ None]
    G -- "< 4.0" --> Low[🟢 Low]
    G -- "< 7.0" --> Med[🟡 Medium]
    G -- "< 9.0" --> High[🟠 High]
    G -- ">= 9.0" --> Crit[🔴 Critical]

    Str["🔤 \"critical\"/\"CRITICAL\"/..."] --> P["ParseSeverity (case-insensitive)"]
    P -- match --> Sev[🏷️ Severity]
    P -- no match --> PE("[🔴 invalid severity]")

    Sev --> Is{🟡 Is* methods}
    Is -- IsNone/IsLow/... --> Bool("[✅ bool]")
```

## 接口参考

### 类型与常量

```go
type Severity string

const (
    SeverityNone     Severity = "None"
    SeverityLow      Severity = "Low"
    SeverityMedium   Severity = "Medium"
    SeverityHigh     Severity = "High"
    SeverityCritical Severity = "Critical"
)
```

### GetSeverity

```go
func GetSeverity(score float64) Severity
```

按 CVSS v3.1 规范将分数映射到桶。这是 `Calculator.GetSeverityRating` 的独立版本——无需 `Calculator` 实例。

| 分数区间 | 严重性 |
| --- | --- |
| `<= 0` | `None` |
| `0.1 – 3.9` | `Low` |
| `4.0 – 6.9` | `Medium` |
| `7.0 – 8.9` | `High` |
| `9.0 – 10.0` | `Critical` |

```go
cvss.GetSeverity(0.0)  // None
cvss.GetSeverity(3.9)  // Low
cvss.GetSeverity(7.5)  // High
cvss.GetSeverity(9.8)  // Critical
```

::: tip 与 CLI 一致
`cvss severity 7.5` 打印 `High`；`cvss severity --format json 9.2` 打印 `{"score":9.2,"severity":"Critical"}`。两者调用相同的阈值。
:::

### ParseSeverity

```go
func ParseSeverity(s string) (Severity, error)
```

将字符串解析为 `Severity`，不区分大小写（`None`、`none`、`NONE` 都映射到 `SeverityNone`）。其它输入返回 `invalid severity: <s> (must be None, Low, Medium, High, or Critical)`。

```go
sev, err := cvss.ParseSeverity("HIGH") // SeverityHigh, nil
```

### 方法

```go
func (s Severity) String() string
func (s Severity) IsNone() bool
func (s Severity) IsLow() bool
func (s Severity) IsMedium() bool
func (s Severity) IsHigh() bool
func (s Severity) IsCritical() bool
```

`String` 返回规范形式（`"High"`）。`Is*` 谓词是对常量的精确相等判断。

```go
sev := cvss.GetSeverity(9.8)
if sev.IsCritical() {
    // 告警
}
```

::: warning Is* 是精确判断，不是"至少"
`sev.IsHigh()` 仅对 `High` 为 `true`，不含 `Critical`。类型没有内置顺序，判断"High 或更高"需用数值分数（如 `score >= 7.0`）或组合谓词：`sev.IsHigh() || sev.IsCritical()`。
:::

## 示例

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 分数 -> 严重性桶。
    for _, score := range []float64{0, 3.9, 4.0, 7.5, 9.8} {
        sev := cvss.GetSeverity(score)
        fmt.Printf("%.1f -> %s\n", score, sev)
    }
    // 0.0 -> None
    // 3.9 -> Low
    // 4.0 -> Medium
    // 7.5 -> High
    // 9.8 -> Critical

    // 解析，不区分大小写。
    sev, err := cvss.ParseSeverity("critical")
    if err != nil {
        panic(err)
    }
    fmt.Println(sev, sev.IsCritical()) // Critical true

    // 从真实向量分数驱动严重性。
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    calc := cvss.NewCalculator(cv)
    score, _ := calc.Calculate()
    fmt.Printf("%.1f (%s)\n", score, cvss.GetSeverity(score)) // 9.8 (Critical)

    // "High 或更高"：组合谓词（无内置顺序）。
    if sev.IsHigh() || sev.IsCritical() {
        fmt.Println("需要 paging")
    }
}
```

## 相关

- [评分](/zh/sdk/scores) —— 分数的来源
- [便捷方法](/zh/sdk/convenience) —— `SameSeverity` 比较两向量的桶
- [评分计算器](/zh/sdk/calculator) —— `GetSeverityRating`，方法形式
- CLI：[`severity`](/zh/cli/commands/severity) 与 [`score`](/zh/cli/commands/score)
