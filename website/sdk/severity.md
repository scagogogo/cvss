---
title: Severity
description: cvss.Severity type, SeverityNone/Low/Medium/High/Critical constants, GetSeverity, ParseSeverity, and the IsNone/IsLow/IsMedium/IsHigh/IsCritical methods.
---

# 🏷️ Severity

🏷️ Feature · `pkg/cvss`

`Severity` is the string-typed rating a CVSS score maps to. `GetSeverity` maps a `float64` score to its bucket; `ParseSeverity` parses a string into the type; the `Is*` methods make bucket checks read like English. The thresholds follow the CVSS v3.1 specification.

## Synopsis

```go
sev := cvss.GetSeverity(7.5)              // High
sev, _ := cvss.ParseSeverity("critical") // SeverityCritical
fmt.Println(sev.IsHigh())                 // false
```

## How It Works

`GetSeverity` applies the CVSS v3.1 threshold ladder (None=0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0). `ParseSeverity` is case-insensitive across the five names and the `Is*` methods are direct equality checks against the constants.

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

## API Reference

### Type & constants

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

Maps a score to a bucket per the CVSS v3.1 spec. This is the standalone version of `Calculator.GetSeverityRating` — no `Calculator` instance needed.

| Score range | Severity |
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

::: tip Matches the CLI
`cvss severity 7.5` prints `High`; `cvss severity --format json 9.2` prints `{"score":9.2,"severity":"Critical"}`. Both call the same thresholds.
:::

### ParseSeverity

```go
func ParseSeverity(s string) (Severity, error)
```

Parses a string into `Severity`, case-insensitive (`None`, `none`, `NONE` all map to `SeverityNone`). Anything else returns `invalid severity: <s> (must be None, Low, Medium, High, or Critical)`.

```go
sev, err := cvss.ParseSeverity("HIGH") // SeverityHigh, nil
```

### Methods

```go
func (s Severity) String() string
func (s Severity) IsNone() bool
func (s Severity) IsLow() bool
func (s Severity) IsMedium() bool
func (s Severity) IsHigh() bool
func (s Severity) IsCritical() bool
```

`String` returns the canonical form (`"High"`). The `Is*` predicates are exact-equality checks against the constants.

```go
sev := cvss.GetSeverity(9.8)
if sev.IsCritical() {
    // alert
}
```

::: warning Is* is exact, not "at least"
`sev.IsHigh()` is `true` only for `High`, not for `Critical`. There is no built-in ordering, so "High or worse" requires checking the numeric score (e.g. `score >= 7.0`) or combining predicates: `sev.IsHigh() || sev.IsCritical()`.
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
    // Score -> severity bucket.
    for _, score := range []float64{0, 3.9, 4.0, 7.5, 9.8} {
        sev := cvss.GetSeverity(score)
        fmt.Printf("%.1f -> %s\n", score, sev)
    }
    // 0.0 -> None
    // 3.9 -> Low
    // 4.0 -> Medium
    // 7.5 -> High
    // 9.8 -> Critical

    // Parse, case-insensitive.
    sev, err := cvss.ParseSeverity("critical")
    if err != nil {
        panic(err)
    }
    fmt.Println(sev, sev.IsCritical()) // Critical true

    // Drive severity from a real vector's score.
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    calc := cvss.NewCalculator(cv)
    score, _ := calc.Calculate()
    fmt.Printf("%.1f (%s)\n", score, cvss.GetSeverity(score)) // 9.8 (Critical)

    // "High or worse": combine predicates (no built-in ordering).
    if sev.IsHigh() || sev.IsCritical() {
        fmt.Println("needs paging")
    }
}
```

## Related

- [Scores](/sdk/scores) — where the score comes from
- [Convenience](/sdk/convenience) — `SameSeverity` compares two vectors' buckets
- [Scoring (calculator)](/sdk/calculator) — `GetSeverityRating`, the method form
- CLI: [`severity`](/cli/commands/severity) and [`score`](/cli/commands/score)
