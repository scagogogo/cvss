---
title: Impact & Sensitivity
description: cvss.ImpactAnalysis, SensitivityAnalysis, FindMetricChangesToReachTarget, and the MetricImpact/ValueImpact/MetricChange/MetricSensitivity types.
---

# 🎯 Impact & Sensitivity

Single-vector analysis: given one `*Cvss3x`, which base metric moves the score the most? `ImpactAnalysis` shows per-value deltas, `SensitivityAnalysis` shows each metric's score swing, and `FindMetricChangesToReachTarget` proposes the smallest set of changes to reach a target score.

## Synopsis

```go
impacts, _   := cvss.ImpactAnalysis(cv)          // per-value deltas, sorted by |delta|
sensitivities, _ := cvss.SensitivityAnalysis(cv)  // min..max swing per metric
changes, _   := cvss.FindMetricChangesToReachTarget(cv, 7.0)
```

All three operate on the **base** score only (the 8 base metrics).

## How It Works

All three functions clone the vector, swap one base metric value at a time, and re-score with a fresh `Calculator`. `ImpactAnalysis` records per-value deltas and sorts by max `|delta|`; `SensitivityAnalysis` records each metric's min/max; `FindMetricChangesToReachTarget` greedily picks the largest in-direction delta until the target is reached (tolerance 0.05).

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

## Types

### `MetricImpact`

| Field | Type | Meaning |
| --- | --- | --- |
| `Metric` | `string` | Short name, e.g. "AV" |
| `CurrentVal` | `string` | Current short value |
| `CurrentScore` | `float64` | Current base score |
| `ValueImpacts` | `[]ValueImpact` | One entry per alternative value |

### `ValueImpact`

| Field | Type | Meaning |
| --- | --- | --- |
| `Value` | `string` | Alternative short value |
| `LongValue` | `string` | e.g. "Adjacent" |
| `Score` | `float64` | Base score if this value were chosen |
| `Delta` | `float64` | `Score - CurrentScore` (positive = higher) |
| `Severity` | `Severity` | Severity at that score |

### `MetricSensitivity`

| Field | Type | Meaning |
| --- | --- | --- |
| `Metric` | `string` | Short name |
| `MinScore` | `float64` | Lowest base score across this metric's values |
| `MaxScore` | `float64` | Highest base score across this metric's values |
| `BaseScore` | `float64` | Current base score |
| `ScoreSwing` | `float64` | `MaxScore - MinScore` |

### `MetricChange`

| Field | Type | Meaning |
| --- | --- | --- |
| `Metric` | `string` | Short name |
| `From` | `string` | Original value |
| `To` | `string` | Proposed value |
| `Delta` | `float64` | Score change |
| `ResultScore` | `float64` | Score after the change |
| `Severity` | `Severity` | Severity after the change |

Each type has a `String()` for readable output.

## API Reference

```go
func ImpactAnalysis(cv *Cvss3x) ([]MetricImpact, error)
func SensitivityAnalysis(cv *Cvss3x) ([]MetricSensitivity, error)
func FindMetricChangesToReachTarget(cv *Cvss3x, targetScore float64) ([]MetricChange, error)
```

- `ImpactAnalysis` returns impacts sorted by the largest absolute delta (most influential metric first).
- `SensitivityAnalysis` returns sensitivities sorted by `ScoreSwing` descending.
- `FindMetricChangesToReachTarget` greedily picks, per metric in impact order, the value that moves toward `targetScore` by the largest step. Stops within a 0.05 tolerance. Returns `nil` if already within tolerance.

::: tip Only base metrics are explored
These functions iterate the 8 base metrics (`AV, AC, PR, UI, S, C, I, A`) and their legal values. Temporal and environmental metrics are not perturbed. Use `SetMetricValue` manually if you need to explore those.
:::

::: warning FindMetricChangesToReachTarget is a heuristic
It applies one change at a time in impact order and re-reads the score after each. It does not guarantee the globally minimal set of changes, and may overshoot when metrics interact (e.g. Scope changes flip PR scoring).
:::

## Example

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    // Which metric moves the score the most?
    impacts, _ := cvss.ImpactAnalysis(cv)
    fmt.Println("most influential:", impacts[0].Metric, impacts[0].ValueImpacts)

    // Score swing per metric.
    for _, s := range must(cvss.SensitivityAnalysis(cv)) {
        fmt.Printf("%s: %.1f ~ %.1f (swing %.1f)\n",
            s.Metric, s.MinScore, s.MaxScore, s.ScoreSwing)
    }

    // How to drop to <= 6.9?
    changes, _ := cvss.FindMetricChangesToReachTarget(cv, 6.9)
    for _, c := range changes {
        fmt.Println(c.String())
    }
}

func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }
```

## Related

- [Scoring (calculator)](/sdk/calculator) — recomputes the score for each perturbation
- [Distance & Comparison](/sdk/distance) — two-vector comparison instead of single-vector impact
- [Score Range](/sdk/score-range) — best/worst case for incomplete vectors
