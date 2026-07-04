---
title: strip / base-only — Keep Base Metrics Only
description: Strip temporal and environmental metrics from a CVSS vector, keeping only the eight base metrics.
---

# ✂️ strip

✂️ Strip · 🟢 stable

## Synopsis

`cvss strip` (alias `base-only`) removes temporal and environmental metrics from a CVSS vector, keeping only the eight base metrics (`AV`/`AC`/`PR`/`UI`/`S`/`C`/`I`/`A`). Use it to normalize a full vector down to its base form before comparing, scoring, or storing.

## How It Works

All temporal and environmental metrics are dropped, leaving only the eight base metrics; the result is a minimal base vector.

```mermaid
flowchart TD
    V["💻 full vector<br/>.../E:F/RL:T/RC:C/CR:H/..."]:::blue --> P["📦 parse"]:::blue
    P --> Strip["BaseOnly()"]:::blue
    Strip --> Drop["discard E, RL, RC,<br/>CR, IR, AR, MAV...MA"]:::purple
    Drop --> Out(["📊 base-only vector<br/>CVSS:3.1/AV/AC/PR/UI/S/C/I/A"]):::green
    P -. parse error .-> Err(["❌ error"]):::red
    classDef blue fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef green fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef red fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    classDef purple fill:#f9f0ff,stroke:#722ed1,color:#391085
    classDef yellow fill:#fffbe6,stroke:#faad14,color:#874d00
```

## Usage

```bash
cvss base-only [vector-string] [flags]
```

**Aliases:** `base-only`, `strip`

### Flags

| Flag         | Type | Default | Description               |
| ------------ | ---- | ------- | ------------------------- |
| `-h, --help` | bool | `false` | Help for `base-only`      |

::: tip Two names, one command
The canonical command name is `base-only`; `strip` is a built-in alias. Both invoke the same code path, so use whichever reads better in your scripts.
:::

## Examples

::: code-group

```bash [strip temporal metrics]
cvss strip "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
```

```text [output]
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

:::

::: tip Also works on environmental metrics
A vector carrying environmental metrics (`CR`/`IR`/`AR` and any `M*`) is reduced the same way — every non-base metric is dropped, leaving just the base vector.
:::

## Underlying API

Parses the vector with [`parser.ParseString`](/sdk/parser), then calls [`cv.BaseOnly()`](/sdk/cvss), which returns a new `*Cvss3x` containing only the base metrics.

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C")
if err != nil {
    log.Fatal(err)
}

base := cv.BaseOnly()
fmt.Println(base.String()) // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Related

- [merge](/cli/commands/merge) — the inverse operation: add temporal/environmental metrics back
- [convert](/cli/commands/convert) — change the CVSS version instead of the metric set
- [score](/cli/commands/score) — score the stripped base vector
- [BaseOnly](/sdk/cvss) — Go SDK reference
