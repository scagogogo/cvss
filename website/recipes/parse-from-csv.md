---
title: Parse and score CVSS vectors from a CSV file
description: Read CVSS vectors from a CSV file with cvss csv read, then score every row by piping into csv write or batch score.
---

# 📑 Parse and score CVSS vectors from a CSV file

## Problem

Your vulnerability inventory lives in a CSV — one column is the CVSS vector string, alongside CVE IDs, dates, or owners — and you need to score every row and enrich it with the base score and severity.

## Solution

Here's the flow:

```mermaid
flowchart LR
  C[📄 vulns.csv<br/>vector in column 0] --> R[📖 csv read<br/>parse column 0]
  R --> P{row valid?}
  P -- yes ✅ --> V[*Cvss3x per row]
  P -- no ❌ + --lax --> E[⚠️ skip + stderr]
  P -- no, strict --> AB[❌ abort whole read]
  V --> W[✍️ csv write → scored CSV]
  V --> J[🔢 batch score → JSON<br/>join via line field]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef data fill:#f9f0ff,stroke:#722ed1,color:#391085
  classDef warn fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class C in
  class R,W step
  class P branch
  class V data
  class J out
  class E,AB warn
```

### 1. Lay out the CSV with the vector in the first column

`csv read` parses the **first column** of every row as a vector string and skips a header row. Put the vector first:

`vulns.csv`:

```csv
vector,cve
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,CVE-2024-0001
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L,CVE-2024-0002
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L,CVE-2024-0003
```

::: warning Vector must be column 0
`csv read` only reads `record[0]`. A CSV with `cve,vector` (CVE first) prints nothing, because the CVE IDs don't parse as vectors and the header consumes the first data row. Always put the vector in the first column.
:::

### 2. Read and re-emit as a scored CSV

Pipe `csv read` into `csv write`. `csv write` reads vectors from stdin (one per line) and emits a full scored CSV with all sub-scores:

```bash
cvss csv read vulns.csv | cvss csv write
```

```csv
vector_string,version,base_score,base_severity,temporal_score,temporal_severity,environmental_score,environmental_severity,impact_sub_score,exploitability_sub_score
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,3.1,9.8,Critical,,,,,5.8731,3.8870
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L,3.1,5.3,Medium,,,,,1.4124,3.8870
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L,3.1,3.8,Low,,,,,3.3734,0.3330
```

Write it to a file with `-o`:

```bash
cvss csv read vulns.csv | cvss csv write -o scored.csv
```

### 3. Score as JSON and join back to the CVE ID

If you want to keep the CVE ID alongside the score, score as JSON and re-attach the ID with a small join. `batch score` reads vectors from stdin too:

```bash
cvss csv read vulns.csv | cvss batch score - --format json
```

```json
{
  "line": 1,
  "score": 9.8,
  "severity": "Critical",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
{
  "line": 2,
  "score": 5.3,
  "severity": "Medium",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
}
```

`line` matches the row position in `vulns.csv` (minus the header), so you can join `line` back to your original CSV row.

### 4. Tolerate messy rows

If some rows have malformed vectors, `--lax` skips them and reports each on stderr instead of aborting:

```bash
cvss csv read --lax messy.csv | cvss csv write
```

## Discussion

- **Strict by default.** Without `--lax`, the first invalid row fails the whole read. Run `cvss batch validate` on the extracted vector column first if you're unsure.
- **Header detection is heuristic.** `csv read` (lax mode) treats the first row as a header unless it starts with `CVSS:`. A header like `vector,cve` is correctly skipped; a data row that happens to start with `CVSS:` is parsed, not skipped.
- **Other columns are dropped.** `csv read` only emits the parsed vector string, so `cve`, `owner`, etc. are not carried through the pipe. Use the `line` field from `batch score --format json` to join back to the source row, or post-process the CSV directly with `awk`/a script.
- **Go SDK alternative.** `cvss.ReadCSV(r)` returns `[]*Cvss3x`; `cvss.ReadCSVLax(r)` returns `([]*Cvss3x, []CSVReadError, error)`. Use them when you need the parsed objects in-process rather than the scored CSV.

## See Also

- [`csv read`](/cli/commands/csv-read) — reader used here
- [`csv write`](/cli/commands/csv-write) — emits the scored CSV
- [`batch score`](/cli/commands/batch-score) — JSON scoring via stdin
- [Filter Critical vulns](/recipes/filter-critical-vulns)
- [Export to JSON](/recipes/export-to-json)
