---
title: Store CVSS vectors in a database and sort by score
description: Persist CVSS vectors in a SQL column with cvss.Scan/Value (sql.Scanner/driver.Valuer) and sort results by score with NewCvss3xSlice.
---

# 🗄️ Store CVSS vectors in a database and sort by score

## Problem

You want to persist CVSS vectors in a SQL database alongside CVE IDs, read them back as typed `Cvss3x` objects, and return rows ordered by severity — without storing a denormalized `score` column you have to keep in sync.

## Solution

Here's the flow:

```mermaid
flowchart LR
  CV[🔤 Cvss3x object] --> V[✍️ Value → canonical string]
  V --> INS[💾 SQL INSERT<br/>store vector only]
  INS --> DB[(🗄️ vulns table<br/>id + cvss TEXT)]
  DB --> SEL[📖 SELECT cvss FROM vulns]
  SEL --> SC[📥 Scan → Cvss3x<br/>string / []byte / NULL]
  SC --> SL[Cvss3xSlice]
  SL --> SO[🔢 NewCvss3xSlice.Sort<br/>cache scores, no score column]
  SO --> OUT[✅ ordered by severity]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef data fill:#f9f0ff,stroke:#722ed1,color:#391085
  class CV in
  class V,INS,SEL,SC,SL,SO step
  class DB data
  class OUT out
```

### 1. Schema

Store the vector string in a `VARCHAR`/`TEXT` column. A generated/trigger-maintained `score` column is optional — see the discussion for why you usually don't need one.

```sql
CREATE TABLE vulns (
    id    VARCHAR(32)  PRIMARY KEY,
    cvss  TEXT         NOT NULL
);
```

### 2. Write: `Value` (driver.Valuer)

`Cvss3x.Value()` returns the canonical vector string, so you can pass a `*Cvss3x` straight to `db.Exec`. `(*Cvss3x)(nil).Value()` writes SQL `NULL`.

```go
import (
    "database/sql"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func insert(db *sql.DB, id string, v *cvss.Cvss3x) error {
    _, err := db.Exec("INSERT INTO vulns (id, cvss) VALUES (?, ?)", id, v)
    return err
}

// Usage:
//   insert(db, "CVE-2024-0001", cvss.CriticalV31())
//   insert(db, "CVE-2024-0002", cvss.LowV31())
```

### 3. Read: `Scan` (sql.Scanner)

`Cvss3x.Scan` accepts `string`, `[]byte`, or `nil` (NULL → empty `Cvss3x`). Scan into a `cvss.Cvss3x` (not a pointer) so the row value is always materialized:

```go
func listAll(db *sql.DB) ([]*cvss.Cvss3x, error) {
    rows, err := db.Query("SELECT cvss FROM vulns")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []*cvss.Cvss3x
    for rows.Next() {
        var cv cvss.Cvss3x
        if err := rows.Scan(&cv); err != nil {
            return nil, err
        }
        out = append(out, &cv)
    }
    return out, rows.Err()
}
```

### 4. Sort by score with `Cvss3xSlice`

Once you have the slice, sort in memory — `NewCvss3xSlice` scores each vector once and caches the result:

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func printBySeverity(db *sql.DB) error {
    vectors, err := listAll(db)
    if err != nil {
        return err
    }

    // Descending — Critical first (the default).
    slice := cvss.NewCvss3xSlice(vectors...).Sort()
    for i, cv := range slice.Items() {
        fmt.Printf("#%d %.1f %s\n", i+1, slice.ScoreAt(i), cv.String())
    }
    return nil
}
```

For a given input set, the output looks like:

```text
#1 10.0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
#2 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
#3 3.7 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
```

## Discussion

::: tip Don't store a `score` column
A `score` column denormalizes the vector — every metric edit forces a rescore, and a stale score is a silent bug. Store the vector string (single source of truth) and compute scores at read time with `NewCvss3xSlice`. For large tables, paginate and score a page at a time.
:::

- **NULL ↔ empty `Cvss3x`.** `Scan(nil)` produces `Cvss3x{Cvss3xBase: &Cvss3xBase{}}` (not a nil pointer), and a nil `*Cvss3x` writes SQL `NULL`. Use `*Cvss3x` (not `**Cvss3x`) as the scan target.
- **Invalid strings fail the scan.** `Scan` wraps a parse error as `"failed to scan Cvss3x: %w"`, so a corrupt row surfaces during `rows.Scan`. If your column may contain legacy junk, scan into `sql.NullString` first and parse defensively.
- **`ORDER BY` in SQL won't sort by score.** The score isn't a column, and you can't compute CVSS in portable SQL. Either sort in Go with `Cvss3xSlice` (recommended), or maintain a `score REAL` column kept in sync by application code (only if you need server-side pagination by score).
- **Invalid vectors sort to −1.** `NewCvss3xSlice` records `-1` for items that fail `Calculate`; in descending order they sort to the top, so guard with `if slice.ScoreAt(i) < 0 { continue }`.
- **Postgres `?` placeholder.** The examples use `?` (MySQL/SQLite). For PostgreSQL, use `$1`, `$2`; for SQL Server, `@p1`. The `Scan`/`Value` interfaces are driver-agnostic.

## See Also

- [SQL & Sorting](/sdk/sql-sort) — `Scan`/`Value`/`Cvss3xSlice`/`Canonicalize` reference
- [Sort by severity](/recipes/sort-by-severity) — the same sort, CLI + SDK, without a database
- [Export to JSON](/recipes/export-to-json) — turn stored vectors into JSON for an API
- [Generate test data](/recipes/generate-test-data) — seed the `vulns` table with random vectors
