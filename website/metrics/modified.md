---
title: Modified Metrics (M*) — Environmental base-metric overrides
description: The CVSS Modified metrics (MAV/MAC/MPR/MUI/MS/MC/MI/MA) let an environment override the base metrics. A value of X (Not Defined) falls back to the base metric value.
---

# 🔄 Modified Metrics (M*)

🟩 Environmental Metric · 📐 Base-metric override with X fallback

## Definition

The eight Modified metrics let an environment **override** each Base metric to reflect the vulnerability's behaviour in that specific deployment. They are **environmental** metrics. Each `M*` metric mirrors a Base metric; setting it to `X` (Not Defined) tells the scorer to fall back to the corresponding base value unchanged.

## Modified Metrics

| Short Name | Long Name                  | Mirrors Base | `X` (Not Defined) behaviour |
| ---------- | -------------------------- | ------------ | -------------------------- |
| MAV        | Modified Attack Vector     | AV           | Use base AV value          |
| MAC        | Modified Attack Complexity | AC           | Use base AC value          |
| MPR        | Modified Privileges Required | PR         | Use base PR value (scope-aware) |
| MUI        | Modified User Interaction  | UI           | Use base UI value (version-aware) |
| MS         | Modified Scope             | S            | Use base S value           |
| MC         | Modified Confidentiality   | C            | Use base C value           |
| MI         | Modified Integrity         | I            | Use base I value           |
| MA         | Modified Availability      | A            | Use base A value           |

The `X` value carries a static score of **1.0** in `pkg/vector/not_defined_vectors.go`, signalling "no modification" to the environmental formula.

## Score Map

```mermaid
flowchart TB
    Base["🧱 Base Metric (AV/AC/PR/UI/S/C/I/A)"]:::data
    M["🛠️ Modified Metric (MAV/MAC/...)"]:::data

    M -->|Value = X (Not Defined)| Fall["↩️ Fallback: use base value\n(score = 1.0 = no change)"]:::neutral
    M -->|Value != X (override)| Over["⬆️ Override base value"]:::crit

    Base --> Fall
    Base --> Over

    classDef data fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef neutral fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef crit fill:#f9f0ff,stroke:#722ed1,color:#391085
```

Modified metrics carry `X` (Not Defined, score **1.0**), which **falls back** to the base metric value. Any other value **overrides** the base value in the environmental formula.

## Scoring Impact

Each Modified metric, when set to a concrete value, replaces the corresponding base metric in the environmental re-computation of the Base Score. When set to `X`, the base value is used instead — so the metric effectively disappears and the base value flows through. This lets you tailor *only* the dimensions that differ in your environment while leaving the rest at their base values.

Two helpers handle the tricky fallbacks:

- **MPR with `X`**: `GetPrivilegesRequiredScore(mpr, scopeChanged)` returns `1.0` for `X` (or nil), and the environmental formula then re-applies the base PR via the modified-scope resolution. Use `IsModifiedScopeChanged(ms, baseScope)` to determine the correct scope.
- **MUI with `X`**: `GetUserInteractionScore(mui, minorVersion)` returns `1.0` for `X` (or nil), so the base UI value flows through.

## Example

Start from a base Critical vector and override only the Attack Vector to `Local`:

```bash
# Base only (MAV:X falls back to AV:N)
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:X"
# Override attack vector to Local in this environment
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L"
```

```text
Base: 9.8 (Critical), Environmental: 9.8 (Critical)   # MAV:X → base AV:N
Base: 9.8 (Critical), Environmental: 8.4 (High)       # MAV:L overrides
```

With `MAV:X` the environmental score equals the base score (AV:N flows through). Setting `MAV:L` lowers the environmental score to 8.4, reflecting that in this environment the attack can only be launched locally.

Go SDK — fetching the `X` (Not Defined) variant:

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    // The X variant signals "fall back to base".
    mavX, _ := vector.GetModifiedAttackVector('X')
    fmt.Println(mavX.IsNotDefined(), mavX.GetScore()) // true 1.0

    // A concrete override:
    mavL, _ := vector.GetModifiedAttackVector('L')
    fmt.Println(mavL.GetScore()) // 0.55
}
```

## Source

The Modified-metric presets are defined alongside their base counterparts in each metric's `.go` file (e.g. `ModifiedAttackVectorLocal` in `attack_vector.go`). The `X` (Not Defined) variants all live in [`pkg/vector/not_defined_vectors.go`](https://github.com/scagogogo/cvss-skills/blob/main/pkg/vector/not_defined_vectors.go) and share a score of `1.0`.

## Related

- [Metrics Overview](./)
- [Privileges Required (PR)](./privileges-required) — scope-aware fallback
- [User Interaction (UI)](./user-interaction) — version-aware fallback
- [Requirements (CR/IR/AR)](./requirements)
