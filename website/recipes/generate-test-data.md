---
title: Generate random CVSS vectors for test data
description: Generate random CVSS 3.x vectors with the cvss random command and the mock.RandomCvss3xFull Go API for test fixtures and property tests.
---

# 🎲 Generate random CVSS vectors for test data

## Problem

You need CVSS vectors to seed a test database, write property-based tests, or demo a dashboard — but hand-writing valid vectors is tedious and biased toward a few familiar shapes.

## Solution

Here's the flow:

```mermaid
flowchart LR
  R[🎲 random source] --> G{which generator?}
  G -- cvss random --> C1[🔤 base-only vector<br/>default v3.1]
  G -- --temporal --> C2[🔤 + E RL RC]
  G -- --full --> C3[🔤 + temporal + env<br/>all 11 metrics]
  G -- mock.RandomCvss3x* --> C4[⚙️ *Cvss3x object<br/>no re-parse]
  C1 --> V[✅ valid, scoreable vector]
  C2 --> V
  C3 --> V
  C4 --> V
  V --> U[🧪 test DB / fixtures<br/>property tests]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class R in
  class C1,C2,C3,C4 step
  class G branch
  class V,U out
```

### CLI: `random`

`cvss random` emits a valid, base-only v3.1 vector with uniformly random metric values:

```bash
cvss random
```

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:H
```

Each call is different. Useful flags:

```bash
cvss random --score         # include the calculated score
cvss random --temporal      # add E/RL/RC
cvss random --full          # add temporal + environmental
cvss random --cvss-version 3.0   # v3.0 instead of v3.1
cvss random --format json   # {"vector": "..."}
```

```bash
cvss random --score
```

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
Score: 7.1 (High)
```

```bash
cvss random --temporal
```

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:H/RL:T/RC:R
```

```bash
cvss random --format json
```

```json
{
  "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:H"
}
```

Generate a batch by looping:

```bash
for i in $(seq 1 5); do cvss random; done > fixtures.txt
```

### Go SDK: `mock.RandomCvss3xFull`

The `pkg/mock` package gives you objects directly, so you don't have to parse the string back. `RandomCvss3x` is base-only, `RandomCvss3xWithTemporal` adds E/RL/RC, and `RandomCvss3xFull` adds all 11 environmental metrics. The argument is the minor version (`0` or `1`).

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/mock"
)

func main() {
	// Base-only v3.1.
	fmt.Println(mock.RandomCvss3x(1).String())

	// Full (temporal + environmental) v3.1.
	full := mock.RandomCvss3xFull(1)
	fmt.Println(full.String())

	// With score.
	cv, score, err := mock.RandomCvss3xWithScore(1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s -> %.1f\n", cv.String(), score)

	// v3.0 random vector string.
	fmt.Println(mock.RandomCvss3xVectorString(0))
}
```

A sample run:

```text
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:W/RC:R/CR:L/IR:L/AR:M/MAV:X/MAC:H/MPR:H/MUI:N/MS:C/MC:X/MI:H/MA:L
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N -> 5.3
CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:N
```

::: tip Reproducible randomness
`pkg/mock` uses `math/rand` without seeding. For deterministic test fixtures, seed the global source (`rand.Seed(42)`) at the start of your test, or capture generated strings into a golden file once and check that in.
:::

## Discussion

- **Every generated vector is valid and scoreable.** `RandomCvss3xFull` sets every metric to a legal value, so `NewCalculator(cv).Calculate()` never errors on its output.
- **Distribution is uniform per metric, not over scores.** Because each metric is chosen independently, the score distribution is *not* uniform — extreme scores (0.0, 10.0) are rarer than mid-range ones. If you need a vector at a *specific* severity, build it with [`build`](/cli/commands/build) or use a [preset](/cli/commands/preset).
- **`--full` can include `X` (Not Defined).** Environmental metrics include the `X` value, which the calculator treats as "inherit the base metric" — so a full random vector still scores sensibly.
- **Not what you want?** For a fixed vector at a known severity, use the [`preset`](/cli/commands/preset) command or `cvss.CriticalV31()` / `HighV31()` / `MediumV31()` / `LowV31()` / `NoneV31()` in Go.

## See Also

- [`random`](/cli/commands/random) — the CLI command
- [`preset`](/cli/commands/preset) — fixed-severity vectors
- [Mock & Random](/sdk/mock) — `RandomCvss3x` / `RandomCvss3xFull` / `RandomCvss3xWithScore` reference
- [Presets](/sdk/presets) — `CriticalV31` and friends
- [Store in a database](/recipes/store-in-database)
