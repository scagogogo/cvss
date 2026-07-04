---
title: Scoring Formulas
description: The CVSS v3.0/v3.1 scoring formulas — Base = roundup(min(ISC+ESC,10)), with Scope adjustment, plus Temporal and Environmental extensions, traced to pkg/cvss/calculator.go and scores.go.
---

# 🧮 Scoring Formulas

## Synopsis

CVSS produces three layers of scores — **Base**, **Temporal**, and **Environmental** — each a refinement of the previous. This page gives the exact formulas as implemented in `pkg/cvss/calculator.go` and `pkg/cvss/scores.go`, with a flow diagram of the full calculation pipeline.

## Base Score

The Base score depends only on the eight base metrics (AV, AC, PR, UI, S, C, I, A).

### Impact Sub-Score (ISC)

```
ISC_base = 1 - (1 - C) × (1 - I) × (1 - A)
```

If Scope is **Unchanged**:

```
ISC = 6.42 × ISC_base
```

If Scope is **Changed**:

```
ISC = 7.52 × (ISC_base - 0.029) - 3.25 × (ISC_base × 0.9731 - 0.02)^13
```

When all three CIA impacts are `None` (0), `ISC` is forced to `0`.

### Exploitability Sub-Score (ESC)

```
ESC = 8.22 × AV × AC × PR × UI
```

`PR` is **Scope-dependent** — the same `PR` value yields a different score when Scope is Changed vs Unchanged (see `vector.GetPrivilegesRequiredScore`). `UI` is **version-dependent** — `UI:R` is `0.56` under v3.0 and `0.62` under v3.1 (see [v3.0 vs v3.1](./version-diff)).

### Combining into the Base Score

```
if ISC <= 0:  Base = 0
else if Scope Changed:
    Base = roundup( min( 1.08 × (ISC + ESC), 10 ) )
else:
    Base = roundup( min( ISC + ESC, 10 ) )
```

The `1.08` multiplier is applied only when Scope is Changed, reflecting the cross-scope impact amplification.

## Temporal Score

The Temporal score refines the Base score with time-based factors. Unset Temporal metrics default to `1.0` ("Not Defined"):

```
Temporal = roundup( Base × E × RL × RC )
```

| Factor | Metric | Unset default |
|--------|--------|---------------|
| `E`  | Exploit Code Maturity | 1.0 |
| `RL` | Remediation Level     | 1.0 |
| `RC` | Report Confidence     | 1.0 |

## Environmental Score

The Environmental score is the most refined: it re-derives ISC and ESC from **modified** base metrics (prefixed `M`), applies **security requirement** adjustment factors (CR/IR/AR: `0.5`/`1.0`/`1.5` for L/M/H), then multiplies by the Temporal factors:

```
MISC = 6.42 × min(MC×CR, 1) ...    (or the 7.52 Changed formula)
MESC = 8.22 × MAV × MAC × MPR × MUI

if MISC <= 0:  Env = 0
else if Modified Scope Changed:
    Env = roundup( min( 1.08 × (MISC + MESC), 10 ) )
else:
    Env = roundup( min( MISC + MESC, 10 ) )

Environmental = roundup( Env × E × RL × RC )
```

Each `M*` metric falls back to its base counterpart when the value is `X` (Not Defined).

## Calculation Flow

```mermaid
flowchart TD
    Start([Cvss3x vector]) --> Check{Check() valid?}
    Check -- no --> Err([return error])
    Check -- yes --> ISC[calculateImpactSubScore]
    ISC --> ESC[calculateExploitabilitySubScore]
    ESC --> Zero{ISC <= 0?}
    Zero -- yes --> Base0([Base = 0])
    Zero -- no --> Scope{Scope Changed?}
    Scope -- yes --> BaseChg["roundup(min(1.08×(ISC+ESC),10))"]
    Scope -- no --> BaseUn["roundup(min(ISC+ESC,10))"]
    Base0 --> HasT{has Temporal?}
    BaseChg --> HasT
    BaseUn --> HasT
    HasT -- no --> HasE{has Environmental?}
    HasT -- yes --> Temp["calculateTemporalScore<br/>roundup(Base×E×RL×RC)"]
    Temp --> HasE
    HasE -- no --> OutBase([return Base / Temporal])
    HasE -- yes --> Env["calculateEnvironmentalScore<br/>MISC + MESC + CR/IR/AR + E×RL×RC"]
    Env --> OutEnv([return Environmental])
```

## In Code

| Formula piece | Source location |
|---------------|-----------------|
| `calculateBaseScore` | `pkg/cvss/calculator.go` |
| `calculateImpactSubScore` (ISC) | `pkg/cvss/calculator.go` |
| `calculateExploitabilitySubScore` (ESC) | `pkg/cvss/calculator.go` |
| `calculateTemporalScore` | `pkg/cvss/calculator.go` |
| `calculateEnvironmentalScore` + `calculateModifiedImpactSubScore` | `pkg/cvss/calculator.go` |
| `roundUp` (internal) & public `RoundUp` | `pkg/cvss/calculator.go`, `pkg/cvss/scores.go` |
| `GetBaseScore` / `GetTemporalScore` / `GetEnvironmentalScore` | `pkg/cvss/scores.go` |
| `GetImpactSubScore` / `GetExploitabilitySubScore` | `pkg/cvss/scores.go` |
| `GetAllScores` (one-shot all layers) | `pkg/cvss/scores.go` |

### `roundUp` — the CVSS integer algorithm

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

`Roundup(x)` returns the smallest number, specified to one decimal place, that is ≥ `x`. It is exported as `cvss.RoundUp` so external code can round consistently.

### One-shot all scores

```go
calc := cvss.NewCalculator(cv)
all, err := calc.GetAllScores()
// all.BaseScore, all.TemporalScore, all.EnvironmentalScore,
// all.BaseSeverity, all.ImpactSubScore, all.ExploitabilitySubScore, ...
```

`AllScores` also carries `HasTemporal` / `HasEnvironmental` flags and the three severity ratings, computed in a single pass to avoid re-deriving ISC/ESC.

## Example

```bash
$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
10.0 (Critical)

$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
9.8 (Critical)

$ cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
6.5 (Medium)
```

The first vector has Scope Changed (`S:C`), so the `1.08` multiplier is applied; the second is otherwise identical but Scope Unchanged, dropping from `10.0` to `9.8`.

## Related

- [Severity Ratings](./severity) — thresholds applied to the score produced here
- [v3.0 vs v3.1](./version-diff) — the `UI:R` and `roundUp` version branches
- [Go SDK: calculator](/sdk/calculator) — the SDK-facing scoring API
