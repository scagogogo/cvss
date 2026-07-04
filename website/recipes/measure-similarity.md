---
title: Measure similarity between two CVSS vectors
description: Compute Euclidean, Manhattan, Hamming, Jaccard, and score-difference distances between two CVSS vectors with cvss distance and the DistanceCalculator Go API.
---

# 📏 Measure similarity between two CVSS vectors

## Problem

You want a number — not a list of differing metrics — that says how far apart two CVSS vectors are, for de-duplication, clustering, or "find similar advisories."

## Solution

Here's the flow — one calculator, five metrics, choose by use case:

```mermaid
flowchart LR
  V1[🔤 V1] & V2[🔤 V2] --> DC[⚙️ DistanceCalculator<br/>NewDistanceCalculator a, b]
  DC --> M{which metric?}
  M -- count diffs --> H[🔢 Hamming<br/>int 0–11]
  M -- normalized sim --> J[📊 Jaccard<br/>0–1, 1=identical]
  M -- outlier-weighted --> E[📐 Euclidean<br/>√Σ diff²]
  M -- robust to outlier --> MA[📐 Manhattan<br/>Σ|diff|]
  M -- final number only --> SD[🎯 Score diff<br/>|score a − score b|]
  H --> R[📋 rank / cluster / dedup]
  J --> R
  E --> R
  MA --> R
  SD --> R
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class V1,V2 in
  class DC step
  class M branch
  class H,J,E,MA,SD step
  class R out
```

### CLI: `distance`

```bash
cvss distance \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
```

```text
Euclidean:  0.9670
Manhattan:  2.4600
Hamming:    7
Jaccard:    0.1250
Score diff: 6.0
```

Add `--env` to fold the 11 environmental dimensions into the calculation:

```bash
cvss distance --env \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:H/AR:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/E:U/RL:O/RC:R/CR:L/IR:L/AR:L"
```

```text
Euclidean (with env):  1.9850
Manhattan (with env):  5.5700
Hamming (with env):    13
Jaccard (with env):    0.4091
Score diff: 7.4
```

For machine consumption, `--format json`:

```bash
cvss distance --format json \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
```

```json
{
  "euclidean": 0.9669539802906858,
  "hamming": 7,
  "jaccard": 0.125,
  "manhattan": 2.46,
  "score_diff": 6.000000000000001,
  "vector1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vector2": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
}
```

### Go SDK: `DistanceCalculator`

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	a, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b, _ := parser.ParseString("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")

	dc := cvss.NewDistanceCalculator(a, b)
	fmt.Printf("Euclidean : %.4f\n", dc.EuclideanDistance())
	fmt.Printf("Manhattan : %.4f\n", dc.ManhattanDistance())
	fmt.Printf("Hamming   : %d\n", dc.HammingDistance())
	fmt.Printf("Jaccard   : %.4f\n", dc.JaccardSimilarity())
	fmt.Printf("ScoreDiff : %.1f\n", dc.ScoreDifference())

	// Environmental variants
	fmt.Printf("Euclidean (env): %.4f\n", dc.EuclideanDistanceWithEnv())

	// Error-returning variant — surfaces incomplete base metrics
	if _, err := dc.EuclideanDistanceChecked(); err != nil {
		fmt.Println("checked error:", err)
	}
}
```

## Choosing a metric

| Metric | What it measures | Range | Use when |
| --- | --- | --- | --- |
| **Hamming** | count of differing metrics | int 0–11 (base) | you want "how many knobs differ," all differences equal |
| **Jaccard** | same / total metrics | 0–1 (1 = identical) | you want a normalized similarity in [0,1] |
| **Euclidean** | √(Σ score-diff²) | ≥ 0 | you care about *magnitude* of score-space differences, outliers weighted more |
| **Manhattan** | Σ \|score-diff\| | ≥ 0 | same as Euclidean but robust to one large outlier |
| **Score diff** | \|score(a) − score(b)\| | 0–10 | you only care about the final number, single dimension |

::: tip Jaccard is a similarity, not a distance
`JaccardSimilarity` returns `1.0` for identical vectors and `0.0` for fully disjoint ones. Convert to a distance with `1 - jaccard` if you need a dissimilarity that's `0` for identical.
:::

## Discussion

- **Plain variants silently return 0 on incomplete base metrics.** If either vector is missing a required base metric, `EuclideanDistance()` etc. return `0.0` — which looks identical to "identical vectors." Use the `*Checked` variants (`EuclideanDistanceChecked()`) to get an explicit error.
- **PR and UI use context-adjusted scores.** PR's score depends on Scope, and UI:R scores 0.56 in v3.0 vs 0.62 in v3.1 — the distance math accounts for this, so cross-version comparisons are meaningful.
- **Scope is 0/1, not a score.** Scope has no numeric score, so the distance code treats a scope change as a fixed `1.0` contribution.
- **`--env` only adds dimensions when both vectors have environmental metrics.** If only one side has them, the env variants fall back to the base+temporal behavior.
- **Not what you want?** For a per-metric human-readable breakdown, see [Compare two vectors](/recipes/compare-two-vectors).

## See Also

- [`distance`](/cli/commands/distance) — the CLI command
- [Distance & Comparison](/sdk/distance) — `DistanceCalculator` reference (plain / `WithEnv` / `Checked`)
- [Compare two vectors](/recipes/compare-two-vectors)
- [Impact & Sensitivity](/sdk/impact) — single-vector "which metric matters most"
