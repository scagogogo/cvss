---
title: Presets and Random
description: Generate canonical CVSS vectors for each severity level with the preset command, and produce random test vectors with random and the Go mock.RandomCvss3x helper.
---

# 🎲 Presets and Random

⏱️ 12 min · intermediate · CLI + SDK

Two generation tasks come up constantly: producing a "representative" vector for a given severity (for documentation, defaults, or smoke tests), and producing *random* vectors (for property-based tests and demos). The CLI gives you `preset` and `random`; the Go SDK gives you `pkg/mock`. This tutorial exercises both.

## Prerequisites

- The `cvss` binary on your `$PATH` (or `./cvss-cli` from the repo root)
- Finish [getting-started](./getting-started)
- For the SDK section: Go 1.18+

## Flow

```mermaid
flowchart LR
  G{what to generate?} --> P[fixed severity?]
  G --> R[random?]
  P --> PR{cvss preset}
  PR -- critical --> P1[🔟 S:C → 10.0]
  PR -- high --> P2[9️⃣ S:U → 9.8 Critical]
  PR -- medium --> P3[6️⃣ C:L/I:L/A:N → 6.5]
  PR -- low --> P4[3️⃣ AC:H + I:N/A:N → 3.7]
  PR -- none --> P5[0️⃣ C:N/I:N/A:N → 0.0]
  R --> RR{cvss random}
  RR -- base --> RB[🔤 base only]
  RR -- --temporal --> RT[🔤 + E RL RC]
  RR -- --full --> RF[🔤 + env all 11]
  RR -- mock pkg --> RM[⚙️ *Cvss3x direct]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class G branch
  class P,R step
  class PR,RR branch
  class P1,P2,P3,P4,P5,RB,RT,RF,RM step
```

## Step 1 — Preset vectors for each severity

`preset <severity>` prints a canonical vector that lands in the requested severity band. Five levels are supported: `critical`, `high`, `medium`, `low`, `none`. Add `--score` to see the score alongside.

```bash
cvss preset critical --score
cvss preset high --score
cvss preset medium --score
cvss preset low --score
cvss preset none --score
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 10.0 (Critical)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
Score: 6.5 (Medium)
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Score: 3.7 (Low)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
Score: 0.0 (None)
```

Read the progression — each preset is a one-metric lever away from its neighbor:

| Preset | Vector | Score | The lever that creates it |
| --- | --- | --- | --- |
| `critical` | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | `S:C` (changed scope) lifts the cap |
| `high` | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | `S:U` caps ISC at 6.42 |
| `medium` | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | 6.5 | impact dropped to `C:L/I:L/A:N` |
| `low` | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 3.7 | `AC:H` plus `I:N/A:N` |
| `none` | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0.0 | zero impact (`C:N/I:N/A:N`) |

::: warning The "high" preset scores 9.8 Critical
The preset named `high` produces a vector that scores **9.8 (Critical)**, not High. The name refers to the *preset's slot* in the progression, not the resulting severity band. The 9.8→10.0 step is the `S:U`→`S:C` lever, and there is no base-vector combination that lands in the 7.0–8.9 High band using these exact presets — High severity usually comes from temporal/environmental down-scoring of a 9.8 vector, as shown in [scoring-walkthrough](./scoring-walkthrough).
:::

## Step 2 — Preset in v3.0

`--version 3.0` emits the same preset shapes against the v3.0 weights:

```bash
cvss preset --version 3.0 --score high
```

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
```

For `UI:N` presets the v3.0 and v3.1 scores match exactly; only `UI:R` would differ (see [version-migration](./version-migration)).

## Step 3 — Preset as JSON

```bash
cvss preset --format json critical
```

```json
{
  "severity": "critical",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
}
```

The JSON form omits the score — use `--score` for the text form when you need it, or pipe the vector into `cvss score` for the number.

## Step 4 — Random vectors

`random` emits a vector with random metric values. By default it is base-only; flags add temporal and environmental metrics.

```bash
cvss random
```

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:L
```

::: warning Random output is non-deterministic
Every `cvss random` invocation produces a different vector. The outputs shown in this tutorial are samples — your runs will differ. Do not hardcode them in tests; if you need determinism, seed the source or use a preset.
:::

Add `--score` to score the random vector:

```bash
cvss random --score
```

```
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L
Score: 5.1 (Medium)
```

Add temporal metrics with `--temporal`:

```bash
cvss random --temporal --score
```

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:U/RL:T/RC:X
Score: 4.0 (Medium)
```

Add the full environmental layer with `--full` (temporal + environmental + modified metrics):

```bash
cvss random --full --score
```

```
CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L/E:P/RL:T/RC:X/CR:L/IR:H/AR:L/MAV:L/MAC:L/MPR:X/MUI:R/MS:U/MC:L/MI:H/MA:L
Score: 5.6 (Medium)
```

Generate a v3.0 random vector with `--cvss-version 3.0`:

```bash
cvss random --cvss-version 3.0 --full --score
```

JSON form:

```bash
cvss random --format json
```

```json
{
  "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H"
}
```

## Step 5 — Random vectors in Go: `pkg/mock`

For unit tests, the `pkg/mock` package generates random `*Cvss3x` directly — no need to parse a string. Four entry points cover the same tiers as the CLI flags:

| Function | CLI equivalent | Output |
| --- | --- | --- |
| `mock.RandomCvss3x(minor)` | `cvss random` | base only |
| `mock.RandomCvss3xWithTemporal(minor)` | `cvss random --temporal` | base + temporal |
| `mock.RandomCvss3xFull(minor)` | `cvss random --full` | base + temporal + environmental |
| `mock.RandomCvss3xVectorString(minor)` | (string form) | bare vector string |
| `mock.RandomCvss3xWithScore(minor)` | `cvss random --score` | `(*Cvss3x, score, error)` |

`minor` is the CVSS minor version: `1` for v3.1, `0` for v3.0.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/mock"
)

func main() {
	// Base-only random v3.1 vector
	cv := mock.RandomCvss3x(1)
	fmt.Println("base:    ", cv.String())

	// With temporal
	cvt := mock.RandomCvss3xWithTemporal(1)
	fmt.Println("temporal:", cvt.String())

	// Full (temporal + environmental)
	cvf := mock.RandomCvss3xFull(1)
	fmt.Println("full:    ", cvf.String())

	// Vector string only
	fmt.Println("string:  ", mock.RandomCvss3xVectorString(1))

	// With score
	cv2, score, err := mock.RandomCvss3xWithScore(1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("scored:  %s -> %.1f\n", cv2.String(), score)

	// Feed a random vector into a calculator (typical test pattern)
	calc := cvss.NewCalculator(mock.RandomCvss3x(1))
	s, _ := calc.Calculate()
	fmt.Printf("calc:    %.1f\n", s)
}
```

```
base:     CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N
temporal: CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:F/RL:X/RC:U
full:     CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L/E:X/RL:T/RC:C/CR:M/IR:H/AR:M/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:L/MA:N
string:   CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:L
scored:   CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H -> 6.0
calc:     0.0
```

::: tip Mock vectors are random — do not assert exact scores
`mock.RandomCvss3x*` is for filling a calculator pipeline, generating fixtures, or exercising a code path with a *valid* vector. If a test needs a stable score, use a preset or a hand-built vector instead.
:::

## Step 6 — A property-based test pattern

A common use of `mock` is a loop that asserts an invariant over many random vectors — for example, "every valid base vector scores between 0 and 10":

```go
func TestRandomVectorScoreInRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		cv := mock.RandomCvss3x(1)
		score, err := cvss.NewCalculator(cv).Calculate()
		if err != nil {
			t.Fatalf("random vector failed to score: %v", err)
		}
		if score < 0 || score > 10 {
			t.Fatalf("score %.1f out of range for %s", score, cv.String())
		}
	}
}
```

This catches regressions in the scoring formula without you having to enumerate every vector by hand.

## Recap

- `cvss preset <critical|high|medium|low|none>` emits a canonical vector per severity; `--score` shows the score, `--version 3.0` switches spec.
- The `high` preset scores 9.8 (Critical) — the name is the slot, not the band.
- `cvss random` emits random vectors; `--temporal` / `--full` add tiers, `--score` scores, `--cvss-version 3.0` switches spec. Output is non-deterministic.
- In Go, `pkg/mock` provides `RandomCvss3x`, `RandomCvss3xWithTemporal`, `RandomCvss3xFull`, `RandomCvss3xVectorString`, and `RandomCvss3xWithScore` for tests.

## Next

- Use presets as a starting point and modify them in [building-vectors](./building-vectors)
- See how `UI:R` moves scores across versions in [version-migration](./version-migration)
