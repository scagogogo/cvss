---
title: Sort CVSS vectors by severity
description: Order a batch of CVSS vectors by score with the cvss sort command, and the equivalent Go code using Cvss3xSlice.
---

# 🔢 Sort CVSS vectors by severity

## Problem

You have a list of CVSS vectors and want them ordered by score — worst first for triage, or best first for a clean-up report.

## Solution

Here's the flow:

```mermaid
flowchart LR
  V[📄 vectors.txt<br/>one vector per line] --> S[🔢 score every vector<br/>cache scores]
  S --> O{order?}
  O -- default desc 🔽 --> D[✅ highest score first<br/>Critical → None]
  O -- --asc 🔼 --> A[✅ lowest score first<br/>None → Critical]
  O -- invalid → score −1 --> X[⚠️ sorts to top<br/>guard with ScoreAt < 0]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef warn fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class V in
  class S step
  class O branch
  class D,A out
  class X warn
```

### CLI: `sort`

Given `vectors.txt` (one vector per line), `sort` defaults to **descending** (highest score first):

```bash
cvss sort vectors.txt
```

```text
10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
5.3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
3.8  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L
0.0  CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N
```

For ascending order (lowest first), pass `--asc`:

```bash
cvss sort --asc vectors.txt
```

```text
0.0  CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N
3.8  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L
5.3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

`sort` also reads stdin with `-`:

```bash
cat vectors.txt | cvss sort -
```

### Go SDK: `Cvss3xSlice`

`cvss.NewCvss3xSlice` precomputes each vector's score and implements `sort.Interface`. The default is descending; call `.Asc()` before `.Sort()` for ascending.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	v1 := cvss.CriticalV31() // 10.0, S:C
	v2 := cvss.HighV31()     // 9.8,  S:U
	v3 := cvss.LowV31()      // 3.7

	// Descending — Critical first (the default).
	desc := cvss.NewCvss3xSlice(v1, v2, v3).Sort()
	for i, cv := range desc.Items() {
		fmt.Printf("#%d %.1f %s\n", i+1, desc.ScoreAt(i), cv.String())
	}

	// Ascending — lowest first.
	_ = cvss.NewCvss3xSlice(v1, v2, v3).Asc().Sort()
}
```

Output of the descending loop:

```text
#1 10.0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
#2 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
#3 3.7 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
```

`ScoreAt(i)` returns the cached score, so reading scores after sorting is free — no re-calculation.

## Discussion

- **Tie-breaking is not stable by default.** Two vectors scoring 9.8 keep their input order only if you sort with `sort.Stable(slice)` instead of `slice.Sort()` (which uses `sort.Sort`). The CLI `sort` is not stable, so equal-score vectors may appear in any order.
- **Invalid vectors sort to score −1.** `NewCvss3xSlice` records `-1` for items that fail `Calculate`, so in descending order they land at the *top* (−1 > nothing else) — guard with `if slice.ScoreAt(i) < 0 { continue }` if your input may contain incomplete vectors.
- **Scores are cached at construction.** Mutating a vector after building the slice leaves its cached score stale; rebuild the slice if the underlying vectors change.
- **Not what you want?** For filtering rather than sorting, see [Filter Critical vulns](/recipes/filter-critical-vulns). For persisting sorted results to a database, see [Store in a database](/recipes/store-in-database).

## See Also

- [`sort`](/cli/commands/sort) — the CLI command
- [SQL & Sorting](/sdk/sql-sort) — `Cvss3xSlice` API reference
- [Filter Critical vulns](/recipes/filter-critical-vulns)
- [Store in a database](/recipes/store-in-database)
