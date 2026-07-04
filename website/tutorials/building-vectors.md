---
title: Building Vectors
description: Build the same CVSS v3.1 vector three ways in the Go SDK — FromMap, the fluent Builder, and functional Options — and learn when each style fits.
---

# 🏗️ Building Vectors

⏱️ 15 min · intermediate · Go SDK

Parsing a vector string with `parser.ParseString` is the right move when the string already exists. But when your code *computes* a vector — assembling metrics from a scanner, a form, or a database row — you want to build it programmatically. The Go SDK gives you three idioms for that, all producing the same vector. This tutorial builds `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` three ways and compares them.

## Prerequisites

- Go 1.18+ (the module's `go.mod` pins `go 1.18`)
- Finish [getting-started](./getting-started) so the SDK import paths are familiar
- The module on disk: `go get github.com/scagogogo/cvss-skills`

## Flow

```mermaid
flowchart LR
  T[🎯 target<br/>CVSS:3.1/AV:N/.../A:H → 9.8] --> CH{input shape?}
  CH -- map / JSON / DB row --> F[⚙️ FromMap<br/>map[string]string]
  CH -- fixed, readable --> B[⚙️ NewBuilder<br/>fluent .AV().Build]
  CH -- dynamic call site --> O[⚙️ NewCvss3xWithOptions<br/>WithXxx opts...]
  F --> CV[🔤 *Cvss3x]
  B --> CV
  O --> CV
  CV --> CA[🧮 NewCalculator.Calculate]
  CA --> R[✅ 9.8 Critical<br/>identical downstream]
  CV -.-> |ToMap / FromVectorValues| RT[↩️ round-trip helpers]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class T in
  class CH branch
  class F,B,O,CV,CA step
  class R,RT out
```

## The target

Every example below builds this vector and feeds it to a calculator:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   →  9.8 Critical
```

## Step 1 — `cvss.FromMap`: data-shaped input

`FromMap` takes a `map[string]string` whose keys are metric short names (`AV`, `AC`, …) and whose values are short values (`N`, `L`, …). A `version` key (or a `WithVersion` option) sets the spec version.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	m := map[string]string{
		"version": "3.1",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
	}
	cv, err := cvss.FromMap(m)
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

::: tip FromMap is best when the data is already a map
If your input arrives as JSON, a database row, or a `map[string]string` from a form, `FromMap` is the lowest-friction path — no chaining, no builder plumbing. `MustFromMap(m)` is the panic-on-error variant for tests.
:::

## Step 2 — `cvss.NewBuilder()`: fluent chaining

The Builder is a fluent API: each method returns the builder, so you chain calls in one expression. Methods take `rune` values (`'N'`, `'L'`, …) and there is one method per metric.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	cv, err := cvss.NewBuilder().
		Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').
		S('U').C('H').I('H').A('H').
		Build()
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

The builder also has temporal and environmental methods (`E`, `RL`, `RC`, `CR`, `MAV`, …) with the same chaining shape. `Build()` returns the struct and an error; `MustBuild()` panics on error.

::: tip Builder is best for fixed, readable vectors
When the vector is fixed at code-write time (a preset, a test fixture, a documented default), the builder reads top-to-bottom and is easy to audit visually.
:::

## Step 3 — `cvss.NewCvss3xWithOptions`: functional options

The functional-options idiom passes `WithXxx(rune)` options to a variadic constructor. Each metric has a `WithXxx` option (`WithAV`, `WithAC`, …), and `WithVersion31()` / `WithVersion30()` set the version.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	cv, err := cvss.NewCvss3xWithOptions(
		cvss.WithVersion31(),
		cvss.WithAV('N'), cvss.WithAC('L'), cvss.WithPR('N'), cvss.WithUI('N'),
		cvss.WithS('U'), cvss.WithC('H'), cvss.WithI('H'), cvss.WithA('H'),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

::: tip Options are best when the call site varies
Functional options shine when the set of metrics is dynamic — a scanner that conditionally emits temporal metrics, a config struct that maps to options. You can append `WithXxx` to a slice and splat it in: `cvss.NewCvss3xWithOptions(opts...)`. New options can be added without breaking existing callers.
:::

There are also convenience options that set a group at once:

- `WithTemporal(e, rl, rc rune)` — three temporal metrics in one call.
- `WithRequirements(cr, ir, ar rune)` — three requirement metrics in one call.

## Step 4 — Compare the three styles

| Idiom | Input shape | Best for | Variants |
| --- | --- | --- | --- |
| `FromMap(map[string]string)` | a map | JSON / DB rows / forms | `MustFromMap` (panic) |
| `NewBuilder().AV(...).Build()` | chained calls | fixed, readable vectors, test fixtures | `BuildChecked`, `MustBuild` |
| `NewCvss3xWithOptions(opts...)` | option slice | dynamic call sites, library APIs | `MustNewCvss3xWithOptions` (panic) |

All three produce the same `*Cvss3x`, so the calculator, serializer, and comparator work identically downstream. Pairwise string equality confirms it:

```go
// a := FromMap(...), b := NewBuilder()...Build(), c := NewCvss3xWithOptions(...)
a.String() == b.String() // true
b.String() == c.String() // true
```

::: warning Pick one idiom per codebase
The three idioms are interchangeable at the type level, but mixing them in one module makes the code harder to scan. Pick the one that matches your input shape and stick with it.
:::

## Step 5 — Round-trip: `ToMap` and `FromVectorValues`

Two more construction helpers round out the toolkit:

`ToMap()` is the inverse of `FromMap` — it serializes a `Cvss3x` back to a `map[string]string`:

```go
cv, _ := cvss.NewBuilder().Version(3, 1).
	AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').Build()
m := cv.ToMap()
// map[A:H AC:L AV:N C:H I:H PR:N S:U UI:N version:3.1]
```

`FromVectorValues(version string, pairs ...string)` builds from `"KEY:VALUE"` pairs:

```go
cv, err := cvss.FromVectorValues("3.1",
	"AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H")
```

Use `FromVectorValues` when you already have the segments split out (e.g. from a tokenizer) but not a full vector string.

## Recap

- **`FromMap`** — for map-shaped data (JSON, DB, forms).
- **`NewBuilder()`** — for fixed, readable, chainable construction.
- **`NewCvss3xWithOptions`** — for dynamic call sites and library APIs.
- All three return the same `*Cvss3x`; downstream code (calculator, `String()`, `ToMap()`) is identical.
- `MustFromMap` / `MustBuild` / `MustNewCvss3xWithOptions` panic on error — for tests only.

## Next

- Migrate between v3.0 and v3.1 in [version-migration](./version-migration)
- Generate test vectors with `mock.RandomCvss3x` in [presets-and-random](./presets-and-random)
