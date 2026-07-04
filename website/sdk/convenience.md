---
title: Convenience Methods
description: cvss.Cvss3x.Version / Is30 / Is31 / HasTemporalMetrics / HasEnvironmentalMetrics / Equal / Clone / BaseOnly / IsComplete / EqualScore / SameSeverity — the read-only helper family on *Cvss3x.
---

# 🧩 Convenience Methods

🧩 Feature · `pkg/cvss`

The `Cvss3x` type carries a family of small read-only helpers: version probes (`Version`, `Is30`, `Is31`), group presence checks (`HasTemporalMetrics`, `HasEnvironmentalMetrics`), structural comparisons (`Equal`, `IsComplete`), copying (`Clone`, `BaseOnly`), and score-based comparisons (`EqualScore`, `SameSeverity`). They are the building blocks every other feature composes on top of.

## Synopsis

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cv.Is31()              // true
cv.IsComplete()        // true — all 8 base metrics set
clone := cv.Clone()    // deep copy, receiver untouched
clone.Equal(cv)        // true
base := cv.BaseOnly()  // temporal/env stripped
```

## How It Works

The helpers fall into four groups: version probes read `MajorVersion`/`MinorVersion`; presence checks scan the sub-struct pointers for any non-nil vector; `Equal`/`Clone`/`BaseOnly` walk Base/Temporal/Environmental in parallel; the score-based comparisons defer to `Calculator.GetBaseScore` and `GetSeverity`.

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

## API Reference

### Version probes

```go
func (x *Cvss3x) Version() string // "3.0" or "3.1"
func (x *Cvss3x) Is30() bool      // MajorVersion==3 && MinorVersion==0
func (x *Cvss3x) Is31() bool      // MajorVersion==3 && MinorVersion==1
```

### Group presence

```go
func (x *Cvss3x) HasTemporalMetrics() bool      // any of E/RL/RC set
func (x *Cvss3x) HasEnvironmentalMetrics() bool // any of CR/IR/AR/M* set
```

Return `false` when the corresponding sub-struct is `nil` or when no metric in it is set. `GetTemporalVectorString` and the calculator use these to decide which sections to render/compute.

### Structural comparison & copying

```go
func (x *Cvss3x) Equal(other *Cvss3x) bool       // version + all metrics equal
func (x *Cvss3x) Clone() *Cvss3x                 // deep copy
func (x *Cvss3x) BaseOnly() *Cvss3x              // copy with temporal/env removed
func (x *Cvss3x) IsComplete() bool               // all 8 base metrics set
```

`Equal` compares versions and every set metric (via the `Equal` methods on `Cvss3xBase`/`Cvss3xTemporal`/`Cvss3xEnvironmental`). `Clone` copies the struct and its sub-structs; because `vector.Vector` pointers are immutable, sharing them is safe. `BaseOnly` returns a copy retaining only `Cvss3xBase` — handy for comparing a base score against the full score. `IsComplete` checks only the eight base metrics, not version or optional groups.

::: tip IsComplete vs Check
`IsComplete` is a cheap nil-and-presence check on the 8 base metrics. `Check()` (used by the calculator) performs deeper validation. Use `IsComplete` for a quick "can I even attempt to score?" gate.
:::

### Score-based comparison

```go
func (x *Cvss3x) EqualScore(other *Cvss3x) (bool, error)   // same base score?
func (x *Cvss3x) SameSeverity(other *Cvss3x) (bool, error) // same base severity bucket?
```

Both compute the **base** score of each side with a fresh `Calculator` and compare. `EqualScore` compares the numeric score; `SameSeverity` compares the `Severity` bucket (so a 7.1 and a 7.8 are "same severity" — both High). A nil operand makes both sides nil (`true`) only if both are nil; otherwise `(false, nil)` unless one is nil and the other isn't (`x == other`).

```go
same, err := a.SameSeverity(b) // true if both land in e.g. High
```

::: warning These compare base score only
`EqualScore` and `SameSeverity` deliberately use `GetBaseScore`, not the environmental/temporal headline. To compare the full environmental score, score both sides yourself and compare the numbers.
:::

## Example

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

    fmt.Println(cv.Version())               // 3.1
    fmt.Println(cv.Is31(), cv.Is30())       // true false
    fmt.Println(cv.HasTemporalMetrics())    // true (E/RL/RC set)
    fmt.Println(cv.HasEnvironmentalMetrics()) // false
    fmt.Println(cv.IsComplete())            // true

    // Clone is a deep copy; Equal confirms identity of values.
    clone := cv.Clone()
    fmt.Println(clone.Equal(cv)) // true

    // BaseOnly strips temporal/environmental for an apples-to-apples base compare.
    base := cv.BaseOnly()
    fmt.Println(base.HasTemporalMetrics()) // false

    // SameSeverity compares severity buckets, not exact scores.
    other, _ := parser.ParseString("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
    same, _ := cv.SameSeverity(other)
    fmt.Println(same) // true if both land in the same bucket
}
```

## Related

- [Scoring (calculator)](/sdk/calculator) — backs `EqualScore` / `SameSeverity`
- [Severity](/sdk/severity) — the bucket function `SameSeverity` uses
- [Conversion](/sdk/conversion) — `Clone` underpins version conversion
- CLI: [`equal`](/cli/commands/equal)
