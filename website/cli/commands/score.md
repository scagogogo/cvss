---
title: score — Calculate CVSS Scores
description: Calculate base, temporal and environmental CVSS v3.0/v3.1 scores from a vector string, with severity ratings and JSON output.
---

# 🧮 score

🧮 Scoring · 🟢 stable

## Synopsis

`cvss score` calculates the overall CVSS score from a vector string and prints it with its severity rating. Use `--all` to surface base/temporal/environmental scores, or `--breakdown` for a per-metric contribution view. Every mode supports `--format json`.

## How It Works

From a vector string, the command parses and implicitly validates the metrics, hands the result to a calculator, then branches on which score group to report — defaulting to the most specific score actually available.

```mermaid
flowchart TD
    V["💻 vector string<br/>CVSS:3.1/..."]:::blue --> P["📦 parser.ParseString"]:::blue
    P --> Calc["🧮 cvss.NewCalculator"]:::blue
    Calc --> Mode{flags?}:::yellow
    Mode -- "--all" --> All["GetAllScores"]:::blue
    Mode -- "--breakdown" --> BD["GetScoreBreakdown"]:::blue
    Mode -- "(none)" --> Calc1["Calculate"]:::blue
    Calc1 --> Pick{env metrics<br/>present?}:::yellow
    Pick -- yes --> Env(["📊 environmental score<br/>+ severity"]):::green
    Pick -- no --> Pick2{temporal<br/>present?}:::yellow
    Pick2 -- yes --> Temp(["📊 temporal score<br/>+ severity"]):::green
    Pick2 -- no --> Base(["📊 base score<br/>+ severity"]):::green
    All --> Out(["📊 base / temporal / environmental<br/>with severities"]):::green
    BD --> OutBd(["📊 per-metric breakdown"]):::green
    P -. parse error .-> Err(["❌ error"]):::red
    classDef blue fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef green fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef red fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    classDef yellow fill:#fffbe6,stroke:#faad14,color:#874d00
```

## Usage

```bash
cvss score [vector-string] [flags]
```

### Flags

| Flag            | Type   | Default | Description                                     |
| --------------- | ------ | ------- | ----------------------------------------------- |
| `--all`         | bool   | `false` | Show all scores (base, temporal, environmental) with severities |
| `--breakdown`   | bool   | `false` | Show per-metric score breakdown                 |
| `--format`      | string | `text`  | Output format: `text` or `json`                 |
| `-h, --help`    | bool   | `false` | Help for `score`                                |

::: tip Overall score by default
With no flags, the command prints a single overall score and its severity — the environmental score when environmental metrics are present, otherwise the temporal score, otherwise the base score.
:::

## Examples

::: code-group

```bash [overall score]
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
```

```text [output]
10.0 (Critical)
```

:::

::: code-group

```bash [all scores]
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
```

```text [output]
Base: 10.0 (Critical)
```

:::

::: code-group

```bash [json]
cvss score --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
```

```json [output]
{
  "score": 10,
  "severity": "Critical"
}
```

:::

## Underlying API

Parses the vector with [`parser.ParseString`](/sdk/parser), wraps it in a [`cvss.Calculator`](/sdk/calculator) via `cvss.NewCalculator`, then calls `calc.Calculate()` / `calc.GetAllScores()` / `calc.GetScoreBreakdown()` depending on the flags.

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
if err != nil {
    log.Fatal(err)
}

calc := cvss.NewCalculator(cv)
score, _ := calc.Calculate()
fmt.Printf("%.1f (%s)\n", score, cvss.GetSeverity(score))

// all base / temporal / environmental scores + severities
all, _ := calc.GetAllScores()
fmt.Printf("Base: %.1f (%s)\n", all.BaseScore, all.BaseSeverity)

// per-metric contribution
bd, _ := calc.GetScoreBreakdown()
_ = bd
```

## Related

- [severity](/cli/commands/severity) — map a numeric score to a rating
- [subs](/cli/commands/subs) — impact / exploitability sub-scores
- [analyze](/cli/commands/analyze) — how each metric moves the score
- [Scoring calculator](/sdk/calculator) — Go SDK reference
