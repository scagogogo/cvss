---
title: Enumeration
description: cvss.ListAllMetrics/GetMetricInfo/GetValidValues/IsValidMetricValue, and VectorIterator/NewVectorIterator/Next/Reset/TotalCombinations for iterating all 2592 base combinations.
---

# 🔢 Enumeration

Introspect the metric catalog and enumerate every legal base-metric combination. `ListAllMetrics` describes all 22 metrics and their values; `VectorIterator` walks the 2592 (`4×2×3×2×2×3×3×3`) base-vector space.

## Synopsis

```go
for _, m := range cvss.ListAllMetrics() {
    fmt.Println(m.ShortName, m.LongName, m.Group)
}

it := cvss.NewVectorIterator(1) // v3.1
for cv := it.Next(); cv != nil; cv = it.Next() {
    fmt.Println(cv.String())
}
```

## How It Works

`ListAllMetrics` builds a static catalog grouped into Base (8), Temporal (3) and Environmental (11) metrics, each with its legal values and scores. `VectorIterator` is an odometer over the 8 base metrics: it advances the last metric, carries on overflow, and stops after 2592 combinations.

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

## Types

### `MetricInfo`

| Field | Type | Meaning |
| --- | --- | --- |
| `ShortName` | `string` | e.g. "AV" |
| `LongName` | `string` | e.g. "Attack Vector" |
| `Group` | `string` | "Base" / "Temporal" / "Environmental" |
| `Values` | `[]MetricValueInfo` | All legal values for this metric |

### `MetricValueInfo`

| Field | Type | Meaning |
| --- | --- | --- |
| `ShortValue` | `rune` | e.g. `'N'` |
| `LongValue` | `string` | e.g. "Network" |
| `Score` | `float64` | Static score (PR/UI are context-dependent — see warning) |
| `IsNotDefined` | `bool` | `true` for the `X` value |

### `VectorIterator`

Walks the 8 base metrics as a mixed-radix counter. Fields are unexported; use `NewVectorIterator`, `Next`, `Reset`, `TotalCombinations`.

## API Reference

### Catalog

```go
func ListAllMetrics() []MetricInfo
func GetMetricInfo(shortName string) (MetricInfo, error)
func GetValidValues(shortName string) ([]rune, []string, error)
func IsValidMetricValue(shortName string, value rune) bool
```

`ListAllMetrics` returns 22 entries: 8 base (AV, AC, PR, UI, S, C, I, A), 3 temporal (E, RL, RC), 3 requirements (CR, IR, AR), and 8 modified (MAV, MAC, MPR, MUI, MS, MC, MI, MA). `GetValidValues` returns the short-value runes and matching long-value strings. `IsValidMetricValue` is a boolean wrapper.

### Iterator

```go
func NewVectorIterator(minorVersion int) *VectorIterator
func (vi *VectorIterator) Next() *Cvss3x
func (vi *VectorIterator) Reset()
func (vi *VectorIterator) TotalCombinations() int
```

`Next` returns `nil` when exhausted (after yielding all combinations). `Reset` rewinds to the first combination. `TotalCombinations` returns 2592 for the base space.

::: tip Property testing over the score engine
Feed `VectorIterator` output into `NewCalculator` + `Calculate` to assert invariants across the entire base-vector space — e.g. "no base score exceeds 10.0", "Scope Changed always scores ≥ the Unchanged equivalent for the same CIA".
:::

::: warning MetricValueInfo.Score for PR/UI is the static value
The `Score` field on `MetricValueInfo` (and on `vector.Vector.GetScore()`) is the **static** preset score. PR's effective score depends on Scope, and UI's on CVSS version — do not use the cataloged `Score` for those two when computing a real CVSS score. The `Calculator` uses `GetPrivilegesRequiredScore`/`GetUserInteractionScore` instead.
:::

## Example

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
    // Catalog: list every value of the Scope metric.
    info, _ := cvss.GetMetricInfo("S")
    fmt.Println(info.LongName, "in group", info.Group)
    for _, v := range info.Values {
        fmt.Printf("  %c = %s\n", v.ShortValue, v.LongValue)
    }

    // Validate a value.
    fmt.Println("AV:L valid?", cvss.IsValidMetricValue("AV", 'L')) // true
    fmt.Println("AV:Z valid?", cvss.IsValidMetricValue("AV", 'Z')) // false

    // Iterate all 2592 base combinations.
    it := cvss.NewVectorIterator(1)
    fmt.Println("total:", it.TotalCombinations()) // 2592
    count := 0
    for cv := it.Next(); cv != nil; cv = it.Next() {
        count++
    }
    fmt.Println("iterated:", count) // 2592
}
```

## Related

- [pkg/vector](/sdk/vector) — the underlying metric-value objects
- [pkg/mock](/sdk/mock) — random sampling as an alternative to full enumeration
- [Scoring (calculator)](/sdk/calculator) — score each enumerated vector
