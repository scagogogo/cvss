---
title: 影响与敏感性
description: cvss.ImpactAnalysis、SensitivityAnalysis、FindMetricChangesToReachTarget，以及 MetricImpact/ValueImpact/MetricChange/MetricSensitivity 类型。
---

# 🎯 影响与敏感性

单向量分析：给定一个 `*Cvss3x`，哪个基础指标对评分影响最大？`ImpactAnalysis` 展示各值的差值，`SensitivityAnalysis` 展示各指标的评分摆幅，`FindMetricChangesToReachTarget` 给出达到目标评分所需的最小变更集合。

## 简介

```go
impacts, _   := cvss.ImpactAnalysis(cv)          // 各值差值，按 |delta| 排序
sensitivities, _ := cvss.SensitivityAnalysis(cv)  // 各指标 min..max 摆幅
changes, _   := cvss.FindMetricChangesToReachTarget(cv, 7.0)
```

三者都只作用于**基础**评分（8 个基础指标）。

## 工作原理

这三个函数都克隆向量、每次替换一个基础指标取值、并用全新 `Calculator` 重算评分。`ImpactAnalysis` 记录逐取值差值并按最大 `|delta|` 排序；`SensitivityAnalysis` 记录每个指标的 min/max；`FindMetricChangesToReachTarget` 贪心选取同向最大差值直到达到目标（容差 0.05）。

```mermaid
flowchart TD
    CV[📦 *Cvss3x] --> Check[🧮 Check]
    Check -- error --> Err("[🔴 error]")
    Check -- ok --> Base[🔢 GetBaseScore = currentScore]

    Base --> IA["ImpactAnalysis"]
    Base --> SA["SensitivityAnalysis"]
    Base --> FM["FindMetricChangesToReachTarget(target)"]

    IA --> LoopI[🔄 for each base metric, each alt value]
    LoopI --> CloneI[🟢 Clone + modifyBaseMetric]
    CloneI --> ScoreI[🔢 GetBaseScore]
    ScoreI --> Delta[📐 delta = modScore - baseScore]
    Delta --> SortI["📊 sort by max |delta|"]
    SortI --> IAOut("[\"✅ [\"]MetricImpact]")

    SA --> LoopS[🔄 for each base metric, all values]
    LoopS --> CloneS[🟢 Clone + modifyBaseMetric]
    CloneS --> ScoreS[🔢 GetBaseScore]
    ScoreS --> MinMax["📐 track min/max per metric"]
    MinMax --> SortS[📊 sort by swing]
    SortS --> SAOut("[\"✅ [\"]MetricSensitivity]")

    FM --> Need{"🟡 need increase or decrease?"}
    Need --> Greedy[📐 pick largest in-direction delta per metric]
    Greedy --> Until{"🟡 within 0.05 of target?"}
    Until -- no --> Greedy
    Until -- yes --> FMOut("[\"✅ [\"]MetricChange]")
```

## 类型

### `MetricImpact`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `Metric` | `string` | 短名称，如 "AV" |
| `CurrentVal` | `string` | 当前短值 |
| `CurrentScore` | `float64` | 当前基础分 |
| `ValueImpacts` | `[]ValueImpact` | 每个可选值一条 |

### `ValueImpact`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `Value` | `string` | 备选短值 |
| `LongValue` | `string` | 如 "Adjacent" |
| `Score` | `float64` | 若选该值时的基础分 |
| `Delta` | `float64` | `Score - CurrentScore`（正数 = 升高） |
| `Severity` | `Severity` | 该分数下的严重性 |

### `MetricSensitivity`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `Metric` | `string` | 短名称 |
| `MinScore` | `float64` | 该指标所有值中的最低基础分 |
| `MaxScore` | `float64` | 该指标所有值中的最高基础分 |
| `BaseScore` | `float64` | 当前基础分 |
| `ScoreSwing` | `float64` | `MaxScore - MinScore` |

### `MetricChange`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `Metric` | `string` | 短名称 |
| `From` | `string` | 原值 |
| `To` | `string` | 建议值 |
| `Delta` | `float64` | 评分变化量 |
| `ResultScore` | `float64` | 变更后的评分 |
| `Severity` | `Severity` | 变更后的严重性 |

每个类型都有 `String()` 便于阅读。

## 接口参考

```go
func ImpactAnalysis(cv *Cvss3x) ([]MetricImpact, error)
func SensitivityAnalysis(cv *Cvss3x) ([]MetricSensitivity, error)
func FindMetricChangesToReachTarget(cv *Cvss3x, targetScore float64) ([]MetricChange, error)
```

- `ImpactAnalysis` 返回的影响按最大绝对差值排序（影响最大的指标在前）。
- `SensitivityAnalysis` 返回的敏感性按 `ScoreSwing` 降序排列。
- `FindMetricChangesToReachTarget` 按影响顺序，对每个指标贪婪选取朝 `targetScore` 移动步长最大的值。在 0.05 容差内即停止。若已在容差内返回 `nil`。

::: tip 仅探索基础指标
这些函数遍历 8 个基础指标（`AV, AC, PR, UI, S, C, I, A`）及其合法值，不扰动时间与环境指标。如需探索它们，请手动用 `SetMetricValue`。
:::

::: warning FindMetricChangesToReachTarget 是启发式
它按影响顺序每次应用一个变更，并在每次后重新读取评分。不保证全局最小变更集合，且在指标相互影响时（如 Scope 改变会翻转 PR 评分）可能越过目标。
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
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    // 哪个指标对评分影响最大？
    impacts, _ := cvss.ImpactAnalysis(cv)
    fmt.Println("most influential:", impacts[0].Metric, impacts[0].ValueImpacts)

    // 各指标的评分摆幅。
    for _, s := range must(cvss.SensitivityAnalysis(cv)) {
        fmt.Printf("%s: %.1f ~ %.1f (swing %.1f)\n",
            s.Metric, s.MinScore, s.MaxScore, s.ScoreSwing)
    }

    // 如何降到 <= 6.9？
    changes, _ := cvss.FindMetricChangesToReachTarget(cv, 6.9)
    for _, c := range changes {
        fmt.Println(c.String())
    }
}

func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }
```

## 相关

- [评分计算器](/zh/sdk/calculator) —— 为每次扰动重算评分
- [距离与比较](/zh/sdk/distance) —— 双向量比较而非单向量影响
- [评分范围](/zh/sdk/score-range) —— 不完整向量的最好/最坏情况
