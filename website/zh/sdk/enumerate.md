---
title: 枚举
description: cvss.ListAllMetrics/GetMetricInfo/GetValidValues/IsValidMetricValue，以及遍历全部 2592 种基础组合的 VectorIterator/NewVectorIterator/Next/Reset/TotalCombinations。
---

# 🔢 枚举

内省指标目录并枚举每种合法基础指标组合。`ListAllMetrics` 描述全部 22 个指标及其值；`VectorIterator` 遍历 2592（`4×2×3×2×2×3×3×3`）种基础向量空间。

## 简介

```go
for _, m := range cvss.ListAllMetrics() {
    fmt.Println(m.ShortName, m.LongName, m.Group)
}

it := cvss.NewVectorIterator(1) // v3.1
for cv := it.Next(); cv != nil; cv = it.Next() {
    fmt.Println(cv.String())
}
```

## 工作原理

`ListAllMetrics` 构建一份静态目录，按基础（8）、时间（3）、环境（11）指标分组，各自带合法取值与评分。`VectorIterator` 是 8 个基础指标的里程表：推进最后一个指标，溢出则进位，2592 种组合后停止。

```mermaid
flowchart TD
    subgraph Catalog[ListAllMetrics]
        Base["🟦 Base: AV AC PR UI S C I A"]
        Temp["🟪 Temporal: E RL RC"]
        Env["🟨 Environmental: CR IR AR + MAV..MA"]
        Base --> MI["📊 []MetricInfo"]
        Temp --> MI
        Env --> MI
    end
    subgraph Iter[VectorIterator]
        Init[🟢 NewVectorIterator minorVersion] -> Curr[🟣 current index per metric]
        Curr --> Next1["🔢 Next: build *Cvss3x from current indices"]
        Next1 --> Advance["🔄 advance: increment last index, carry on overflow"]
        Advance --> Done{"🟡 all wrapped?"}
        Done -- no --> Next1
        Done -- yes --> End("[⏹️ return nil]")
        Next1 --> Out("[✅ *Cvss3x]")
    end
```

## 类型

### `MetricInfo`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `ShortName` | `string` | 如 "AV" |
| `LongName` | `string` | 如 "Attack Vector" |
| `Group` | `string` | "Base" / "Temporal" / "Environmental" |
| `Values` | `[]MetricValueInfo` | 该指标的全部合法值 |

### `MetricValueInfo`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `ShortValue` | `rune` | 如 `'N'` |
| `LongValue` | `string` | 如 "Network" |
| `Score` | `float64` | 静态分数（PR/UI 依赖上下文——见警告） |
| `IsNotDefined` | `bool` | 对 `X` 值为 `true` |

### `VectorIterator`

以混合进制计数器遍历 8 个基础指标。字段未导出；使用 `NewVectorIterator`、`Next`、`Reset`、`TotalCombinations`。

## 接口参考

### 目录

```go
func ListAllMetrics() []MetricInfo
func GetMetricInfo(shortName string) (MetricInfo, error)
func GetValidValues(shortName string) ([]rune, []string, error)
func IsValidMetricValue(shortName string, value rune) bool
```

`ListAllMetrics` 返回 22 条：8 个基础（AV、AC、PR、UI、S、C、I、A）、3 个时间（E、RL、RC）、3 个需求（CR、IR、AR）、8 个修改（MAV、MAC、MPR、MUI、MS、MC、MI、MA）。`GetValidValues` 返回短值 rune 与对应长名字符串。`IsValidMetricValue` 是其布尔包装。

### 迭代器

```go
func NewVectorIterator(minorVersion int) *VectorIterator
func (vi *VectorIterator) Next() *Cvss3x
func (vi *VectorIterator) Reset()
func (vi *VectorIterator) TotalCombinations() int
```

`Next` 在穷尽后（即产出全部组合后）返回 `nil`。`Reset` 回到首个组合。`TotalCombinations` 对基础空间返回 2592。

::: tip 对评分引擎做性质测试
把 `VectorIterator` 的输出喂给 `NewCalculator` + `Calculate`，在整个基础向量空间上断言不变量——如"没有基础分超过 10.0"、"对相同 CIA，Scope Changed 的分数始终 ≥ Unchanged"。
:::

::: warning PR/UI 的 MetricValueInfo.Score 是静态值
`MetricValueInfo`（以及 `vector.Vector.GetScore()`）上的 `Score` 字段是**静态**预设分数。PR 的有效分数依赖 Scope，UI 的依赖 CVSS 版本——计算真实 CVSS 分数时，这两个指标请勿使用目录中的 `Score`。`Calculator` 内部使用 `GetPrivilegesRequiredScore`/`GetUserInteractionScore`。
:::

## 示例

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
    // 目录：列出 Scope 指标的每个值。
    info, _ := cvss.GetMetricInfo("S")
    fmt.Println(info.LongName, "in group", info.Group)
    for _, v := range info.Values {
        fmt.Printf("  %c = %s\n", v.ShortValue, v.LongValue)
    }

    // 校验某个值。
    fmt.Println("AV:L valid?", cvss.IsValidMetricValue("AV", 'L')) // true
    fmt.Println("AV:Z valid?", cvss.IsValidMetricValue("AV", 'Z')) // false

    // 遍历全部 2592 种基础组合。
    it := cvss.NewVectorIterator(1)
    fmt.Println("total:", it.TotalCombinations()) // 2592
    count := 0
    for cv := it.Next(); cv != nil; cv = it.Next() {
        count++
    }
    fmt.Println("iterated:", count) // 2592
}
```

## 相关

- [pkg/vector](/zh/sdk/vector) —— 底层指标值对象
- [pkg/mock](/zh/sdk/mock) —— 用随机采样代替穷举
- [评分计算器](/zh/sdk/calculator) —— 为每个枚举向量评分
