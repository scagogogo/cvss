---
title: parse — Parse a CVSS Vector
description: Parse a CVSS v3.0/v3.1 vector string and report its version, completeness, temporal/environmental presence and human description.
---

# 🔍 parse

🔍 Parse · 🟢 stable

## Synopsis

`cvss parse` parses a CVSS vector string and reports its version, whether it is complete, and whether temporal/environmental metrics are present, followed by the normalized vector string and a human-readable description. By default it requires the `CVSS:3.x/` prefix; `--relaxed` accepts a bare metric list and assumes a configurable default version.

## How It Works

The string is routed to a strict or relaxed parser: strict demands the `CVSS:3.x/` prefix; relaxed accepts a bare metric list with a default version. Both yield a `Cvss3x` or an error (bad magic head, duplicate metrics, illegal values).

```mermaid
flowchart TD
    V["💻 input string"]:::blue --> Mode{--relaxed?}:::yellow
    Mode -- no --> Strict["📦 ParseString<br/>(requires CVSS: prefix)"]:::blue
    Mode -- yes --> Relax["📦 ParseRelaxed<br/>+ default-version"]:::blue
    Strict --> Chk{valid?}:::yellow
    Relax --> Chk
    Chk -- yes --> Out(["📊 Cvss3x:<br/>version · complete · groups<br/>+ normalized vector"]):::green
    Chk -- no --> Err(["❌ error:<br/>bad magic head /<br/>duplicate metric / illegal value"]):::red
    classDef blue fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef green fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef red fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    classDef yellow fill:#fffbe6,stroke:#faad14,color:#874d00
```

## Usage

```bash
cvss parse [vector-string] [flags]
```

### Flags

| Flag                  | Type   | Default | Description                                       |
| --------------------- | ------ | ------- | ------------------------------------------------- |
| `--default-version`   | string | `3.1`   | Default version used for relaxed parsing          |
| `-h, --help`          | bool   | `false` | Help for `parse`                                  |
| `--relaxed`           | bool   | `false` | Parse without the `CVSS:` prefix                  |

## Examples

::: code-group

```bash [full vector]
cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
```

```text [output]
Version: 3.1
Complete: true
Has Temporal: true
Has Environmental: false

Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C

Description:
Attack Vector: Network, Attack Complexity: Low, Privileges Required: None, User Interaction: None, Scope: Unchanged, Confidentiality: High, Integrity: High, Availability: High, Exploit Code Maturity: Unproven, Remediation Level: Official Fix, Report Confidence: Confirmed
```

:::

::: code-group

```bash [relaxed, partial vector]
cvss parse --relaxed "AV:N/AC:L"
```

```text [output]
Version: 3.1
Complete: false
Has Temporal: false
Has Environmental: false

Vector String: CVSS:3.1/AV:N/AC:L

Description:
Attack Vector: Network, Attack Complexity: Low
```

:::

::: warning Relaxed parsing needs a default version
Without the `CVSS:` prefix the version is unknown, so `--relaxed` falls back to `--default-version` (default `3.1`). Pass `--default-version 3.0` if your bare vectors are v3.0.
:::

## Underlying API

Strict parsing uses [`parser.ParseString`](/sdk/parser); relaxed parsing uses [`parser.ParseRelaxed(str, defaultVersion)`](/sdk/parser). Completeness and temporal/environmental presence come from `cv.IsComplete()`, `cv.HasTemporalMetrics()` and `cv.HasEnvironmentalMetrics()`; the vector string from `cv.String()`; the description from `cv.Description()`.

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

// strict — requires CVSS: prefix
cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C")

// relaxed — no prefix, default version 3.1
cv, err = parser.ParseRelaxed("AV:N/AC:L", "3.1")

fmt.Println("Version:", cv.Version())
fmt.Println("Complete:", cv.IsComplete())
fmt.Println("Has Temporal:", cv.HasTemporalMetrics())
fmt.Println("Has Environmental:", cv.HasEnvironmentalMetrics())
fmt.Println("Vector String:", cv.String())
fmt.Println("Description:", cv.Description())
```

## Related

- [validate](/cli/commands/validate) — also reports missing/invalid metrics, with pass/fail
- [describe](/cli/commands/describe) — description-only view (no version/completeness)
- [parser package](/sdk/parser) — Go SDK reference
