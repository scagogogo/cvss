---
title: Batch Scoring
description: cvss.BatchScore / BatchAllScores — score many CVSS vectors concurrently with a worker pool; workerCount caps the parallelism and <=0 means len(vectors).
---

# ⚡ Batch Scoring

⚡ Feature · `pkg/cvss`

`BatchScore` and `BatchAllScores` run the CVSS scoring pipeline across a slice of `*Cvss3x` vectors using a fixed-size worker pool. Each result carries the original index so callers can rejoin input and output, plus an `Error` field so one bad vector never aborts the batch.

## Synopsis

```go
results := cvss.BatchScore([]*cvss.Cvss3x{a, b, c}, 4)
for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: %v", r.Index, r.Error)
        continue
    }
    fmt.Printf("index %d: %.1f (%s)\n", r.Index, r.Score, r.Severity)
}
```

`workerCount` controls concurrency. `workerCount <= 0` uses `len(vectors)`, and values larger than the slice are clamped down to `len(vectors)`. A `nil` entry in the input slice yields a result with `Error = ErrNilReceiver` rather than a panic. Results are returned in input order — the goroutines write to `results[idx]`, not to a shared append target.

## API Reference

### BatchScore

```go
func BatchScore(vectors []*Cvss3x, workerCount int) []BatchScoreResult
```

Scores each vector with `NewCalculator(v).Calculate()` and tags it with `GetSeverity(score)`. Returns `nil` for an empty input.

```go
results := cvss.BatchScore(vectors, 0) // 0 => len(vectors) workers
```

### BatchScoreResult

```go
type BatchScoreResult struct {
    Index    int       // original input index
    Vector   *Cvss3x   // original CVSS object (nil if input was nil)
    Score    float64   // score, 0 on failure
    Severity Severity  // severity rating
    Error    error     // scoring error, nil on success
}
```

### BatchAllScores

```go
func BatchAllScores(vectors []*Cvss3x, workerCount int) []BatchAllScoresResult
```

Computes the full `*AllScores` for each vector (base/temporal/environmental + sub-scores) via `Calculator.GetAllScores`. Use this when you need more than the headline number.

```go
all := cvss.BatchAllScores(vectors, 4)
```

### BatchAllScoresResult

```go
type BatchAllScoresResult struct {
    Index  int        // original input index
    Scores *AllScores // full score set, nil on failure
    Error  error      // error
}
```

::: tip Index is your join key
The functions never reorder or drop results. `results[i].Index` always equals the position in the input slice, so you can correlate failures back to the source vector without sorting.
:::

::: warning workerCount is a cap, not a guaranteed pool size
The pool size is `min(workerCount, len(vectors))`. Passing `1000` for a 5-element slice spawns 5 goroutines, not 1000.
:::

## Concurrency Model

```mermaid
flowchart LR
    subgraph Producer
        J["jobs channel<br/>indices 0..N-1"]
    end
    subgraph Workers[workerCount goroutines]
        W1[worker 1]
        W2[worker 2]
        W3[worker ...]
    end
    subgraph Sink
        R["results[idx"]<br/>written by index]
    end
    J --> W1 & W2 & W3
    W1 --> R
    W2 --> R
    W3 --> R
```

A buffered `jobs` channel (capacity `len(vectors)`) feeds indices to `workerCount` goroutines. Each worker pulls an index, scores `vectors[idx]`, and writes the result straight into `results[idx]` — no result channel, no reordering. `sync.WaitGroup` gates the return.

## Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectors := []*cvss.Cvss3x{
        mustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        mustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        nil, // a nil entry is reported, not panicked
        mustParse("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"),
    }

    results := cvss.BatchScore(vectors, 4)
    for _, r := range results {
        if r.Error != nil {
            log.Printf("index %d failed: %v", r.Index, r.Error)
            continue
        }
        fmt.Printf("index %d: %.1f (%s)\n", r.Index, r.Score, r.Severity)
    }

    // Full score breakdown for every vector at once.
    for _, r := range cvss.BatchAllScores(vectors, 2) {
        if r.Error != nil {
            continue
        }
        fmt.Printf("index %d base=%.1f\n", r.Index, r.Scores.BaseScore)
    }
}

func mustParse(s string) *cvss.Cvss3x {
    cv, err := parser.ParseString(s)
    if err != nil {
        panic(err)
    }
    return cv
}
```

## Related

- [Scoring (calculator)](/sdk/calculator) — what `BatchScore` calls under the hood
- [Scores](/sdk/scores) — the per-vector `AllScores` produced by `BatchAllScores`
- [Severity](/sdk/severity) — the `Severity` field on each result
- CLI: [`batch score`](/cli/commands/batch-score)
