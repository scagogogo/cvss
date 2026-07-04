---
title: 便捷方法
description: cvss.Cvss3x.Version / Is30 / Is31 / HasTemporalMetrics / HasEnvironmentalMetrics / Equal / Clone / BaseOnly / IsComplete / EqualScore / SameSeverity——*Cvss3x 上的只读辅助方法全集。
---

# 🧩 便捷方法

🧩 功能点 · `pkg/cvss`

`Cvss3x` 自带一族小型只读辅助方法：版本探测（`Version`、`Is30`、`Is31`）、分组存在性检查（`HasTemporalMetrics`、`HasEnvironmentalMetrics`）、结构比较（`Equal`、`IsComplete`）、拷贝（`Clone`、`BaseOnly`）以及基于分数的比较（`EqualScore`、`SameSeverity`）。它们是其它功能组合的基础积木。

## 简介

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cv.Is31()              // true
cv.IsComplete()        // true——8 个基础指标全设置
clone := cv.Clone()    // 深拷贝，接收者不变
clone.Equal(cv)        // true
base := cv.BaseOnly()  // 已剥离 temporal/env
```

## 工作原理

这些辅助函数分四组：版本探测读 `MajorVersion`/`MinorVersion`；存在性检查扫描子结构指针是否有任一非 nil 向量；`Equal`/`Clone`/`BaseOnly` 并行遍历基础/时间/环境组；基于评分的比较委托给 `Calculator.GetBaseScore` 与 `GetSeverity`。

```mermaid
flowchart LR
    CV[📦 *Cvss3x] --> Ver["Version / Is30 / Is31"]
    CV --> Pres["HasTemporalMetrics / HasEnvironmentalMetrics / IsComplete"]
    CV --> Struct["Equal / Clone / BaseOnly"]
    CV --> Score["EqualScore / SameSeverity"]

    Ver --> VerOut("[\"✅ string / bool\"]")
    Pres --> AnyNil{"🟡 any non-nil vector in group?"}
    AnyNil --> PresOut("[✅ bool]")
    Struct --> Walk["🟣 walk Base/Temporal/Environmental"]
    Walk --> CloneOut[🟢 new *Cvss3x or bool]
    Score --> Calc[🧮 NewCalculator.GetBaseScore]
    Calc --> Cmp{"🟡 score1 op score2?"}
    Cmp --> ScoreOut("[✅ bool, error]")
```

## 接口参考

### 版本探测

```go
func (x *Cvss3x) Version() string // "3.0" 或 "3.1"
func (x *Cvss3x) Is30() bool      // MajorVersion==3 && MinorVersion==0
func (x *Cvss3x) Is31() bool      // MajorVersion==3 && MinorVersion==1
```

### 分组存在性

```go
func (x *Cvss3x) HasTemporalMetrics() bool      // E/RL/RC 任一已设置
func (x *Cvss3x) HasEnvironmentalMetrics() bool // CR/IR/AR/M* 任一已设置
```

对应子结构为 `nil` 或组内无指标已设置时返回 `false`。`GetTemporalVectorString` 与计算器据此决定渲染/计算哪些区段。

### 结构比较与拷贝

```go
func (x *Cvss3x) Equal(other *Cvss3x) bool       // 版本 + 所有指标相等
func (x *Cvss3x) Clone() *Cvss3x                 // 深拷贝
func (x *Cvss3x) BaseOnly() *Cvss3x              // 仅保留基础指标的副本
func (x *Cvss3x) IsComplete() bool               // 8 个基础指标全设置
```

`Equal` 比较版本与每个已设置指标（通过 `Cvss3xBase`/`Cvss3xTemporal`/`Cvss3xEnvironmental` 上的 `Equal` 方法）。`Clone` 拷贝结构及其子结构；由于 `vector.Vector` 指针不可变，共享是安全的。`BaseOnly` 返回仅保留 `Cvss3xBase` 的副本——便于将基础分与完整分对比。`IsComplete` 只检查 8 个基础指标，不查版本或可选组。

::: tip IsComplete 与 Check 的区别
`IsComplete` 是对 8 个基础指标的轻量 nil 与存在性检查。计算器使用的 `Check()` 执行更深层的校验。`IsComplete` 适合快速判断"能否尝试评分"。
:::

### 基于分数的比较

```go
func (x *Cvss3x) EqualScore(other *Cvss3x) (bool, error)   // 基础分是否相同？
func (x *Cvss3x) SameSeverity(other *Cvss3x) (bool, error) // 基础严重性桶是否相同？
```

二者各用一个新的 `Calculator` 计算**基础**分并比较。`EqualScore` 比较数值；`SameSeverity` 比较严重性桶（7.1 与 7.8 视为"同严重性"——都是 High）。两侧都为 nil 时返回 `(true, nil)`；一侧为 nil 另一侧不为 nil 时返回 `x == other` 的结果。

```go
same, err := a.SameSeverity(b) // 若都落入 High 等则 true
```

::: warning 仅比较基础分
`EqualScore` 与 `SameSeverity` 刻意使用 `GetBaseScore`，而非环境/时间主分数。要比较完整环境分，请自行评分后比较数值。
:::

## 示例

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    cv, err := parser.ParseString(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U/RC:C")
    if err != nil {
        panic(err)
    }

    fmt.Println(cv.Version())                 // 3.1
    fmt.Println(cv.Is31(), cv.Is30())         // true false
    fmt.Println(cv.HasTemporalMetrics())      // true（E/RL/RC 已设置）
    fmt.Println(cv.HasEnvironmentalMetrics()) // false
    fmt.Println(cv.IsComplete())              // true

    // Clone 是深拷贝；Equal 确认值相同。
    clone := cv.Clone()
    fmt.Println(clone.Equal(cv)) // true

    // BaseOnly 剥离 temporal/environmental，便于基础分的对等比较。
    base := cv.BaseOnly()
    fmt.Println(base.HasTemporalMetrics()) // false

    // SameSeverity 比较严重性桶，而非精确分数。
    other, _ := parser.ParseString("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
    same, _ := cv.SameSeverity(other)
    fmt.Println(same) // 若两者落入同一桶则 true
}
```

## 相关

- [评分计算器](/zh/sdk/calculator) —— 支撑 `EqualScore` / `SameSeverity`
- [严重性](/zh/sdk/severity) —— `SameSeverity` 所用的分桶函数
- [版本转换](/zh/sdk/conversion) —— `Clone` 是版本转换的底层
- CLI：[`equal`](/zh/cli/commands/equal)
