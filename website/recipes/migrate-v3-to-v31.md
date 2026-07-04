---
title: Migrate CVSS v3.0 vectors to v3.1
description: Upgrade CVSS 3.0 vectors to 3.1 with cvss convert --to 3.1 and the UpgradeTo31 Go API, noting where scores change.
---

# 🔁 Migrate CVSS v3.0 vectors to v3.1

## Problem

Your backlog of advisories is tagged with CVSS v3.0 vectors, but your tooling now expects v3.1. You need to convert them — and know when the score changes.

## Solution

Here's the flow:

```mermaid
flowchart LR
  V30[🔤 CVSS:3.0/... vector] --> C{convert --to 3.1<br/>UpgradeTo31}
  C --> B[🔁 bump version prefix only<br/>metrics untouched]
  B --> CHK{has UI:R?}
  CHK -- no, UI:N --> S1[✅ score unchanged<br/>e.g. 9.8 → 9.8]
  CHK -- yes, UI:R --> S2[📈 score rises<br/>UI:R 0.56 → 0.62<br/>e.g. 8.5 → 8.8]
  S1 --> V31[🔤 CVSS:3.1/... result]
  S2 --> V31
  V31 -.-> |DowngradeTo30| V30B[↩️ back to CVSS:3.0<br/>string round-trips]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class V30 in
  class C,B step
  class CHK branch
  class S1,S2,V31,V30B out
```

### CLI: `convert --to 3.1`

The vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` has identical metrics in both versions, so its score is unchanged:

```bash
cvss convert --to 3.1 "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

```text
Original:  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
Converted: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
```

But `UI:R` (User Interaction: Required) scores **0.56 in v3.0** and **0.62 in v3.1**, so any vector with `UI:R` moves:

```bash
cvss convert --to 3.1 "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
```

```text
Original:  CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.5)
Converted: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.8)
```

The downgrade goes the other way (8.8 → 8.5):

```bash
cvss convert --to 3.0 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
```

```text
Original:  CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.8)
Converted: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.5)
```

### Go SDK: `UpgradeTo31`

`UpgradeTo31` is sugar for `ConvertToVersion(3, 1)`. It clones the vector and bumps the version — metric values are untouched, but the calculator uses the v3.1 weights on the result.

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	v30, _ := parser.ParseString("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")

	v31, err := v30.UpgradeTo31()
	if err != nil {
		panic(err)
	}
	fmt.Println(v31.String()) // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

	// Downgrade is symmetric.
	back, _ := v31.DowngradeTo30()
	fmt.Println(back.String()) // CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

	_ = cvss.NewCalculator
}
```

`ConvertToVersion` only accepts `3.0` and `3.1`; any other version returns `unsupported version: %d.%d`.

## Discussion

- **Only `UI:R` changes the score.** The v3.0→v3.1 spec change that affects scoring is the `UI:Required` weight (0.56 → 0.62). Vectors with `UI:N` (the common case) keep their exact score after conversion.
- **Severity band may shift.** A v3.0 vector at 8.9 (High) with `UI:R` can become 9.x (Critical) after upgrade. Always re-check the severity, not just the score, after migrating.
- **Metric values are not changed.** `convert` is a version bump, not a metric re-interpretation — if your v3.0 vector had `E:F`, the v3.1 result still has `E:F`.
- **Bulk migration.** Wrap `convert` in a shell loop over `vectors.txt`, or call `UpgradeTo31` in a `ReadCSV`→`WriteCSV` pipeline. Score the converted vectors with [Parse from CSV](/recipes/parse-from-csv) afterward.
- **Not what you want?** If you're comparing a v3.0 and a v3.1 vector of the same CVE, use [Compare two vectors](/recipes/compare-two-vectors) — `diff` works across versions.

## See Also

- [`convert`](/cli/commands/convert) — the CLI command
- [Conversion](/sdk/conversion) — `ConvertToVersion` / `UpgradeTo31` / `DowngradeTo30` reference
- [Compare two vectors](/recipes/compare-two-vectors)
- [Parse from CSV](/recipes/parse-from-csv)
