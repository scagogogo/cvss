# Performance API Reference

This document covers performance-related APIs and patterns in CVSS Skills: the concurrent batch helpers in `pkg/parser`, the cost model of the parser/calculator, and how to benchmark with the Go standard library.

## Overview

CVSS Skills does **not** ship a custom benchmarker, object pool, or cache type — those concerns are left to your application. What the library *does* provide is:

- **Concurrent batch helpers** in `pkg/parser` — `BatchParse` and `BatchValidate` run worker goroutines for you.
- **Cheap, per-call construction** — `Cvss3xParser` and `Calculator` bind their input at construction and are not reused across vectors, so there is no pool to draw from and no need for one.
- **One-shot convenience functions** — `ParseString`, `ParseAndValidate`, `ParseAndScore`, etc. collapse multi-step flows into a single call.

For benchmarking and profiling, use the Go standard library's `testing.B` and `runtime/pprof` — see [Benchmarking](#benchmarking) below.

## Cost Model

Understanding what each object binds is key to writing performant code:

| Object | Binds input at | Can be reused? | Thread-safe? |
| ------ | -------------- | -------------- | ------------ |
| `parser.Cvss3xParser` | construction (`NewCvss3xParser(str)`) | No — there is no `SetVector`; construct a fresh parser per vector | A parser is not shared across goroutines |
| `cvss.Calculator` | construction (`NewCalculator(cv)`) | No — bound to one `*Cvss3x` | A calculator is not shared across goroutines |
| `*cvss.Cvss3x` | parse time | Read-only after parse; **safe to share** for concurrent reads | Yes (read-only) |

::: tip No `SetVector`, no pool
Because `Cvss3xParser` binds its input string in the constructor and cannot rebind it, a "parser pool" would gain nothing — you would still construct a fresh parser per vector. The same goes for `Calculator`, which binds a `*Cvss3x` at construction. The idiomatic pattern is simply to call `parser.ParseString(v)` per input; each call builds a short-lived, cheap parser.
:::

The parsed `*Cvss3x`, by contrast, is immutable after a successful parse and safe to hand to many goroutines for read-only access (scoring, comparison, JSON serialization).

## Batch Helpers

The `pkg/parser` package provides two concurrent helpers for bulk processing. Both spin up a fixed worker pool, preserve input order in the results, and collect per-input errors.

### BatchParse

```go
func BatchParse(vectors []string, workerCount int) []BatchParseResult
```

Concurrently parses a slice of CVSS vector strings. `workerCount` controls the goroutine count; if `workerCount <= 0`, it defaults to `len(vectors)`; if it exceeds the input length, it is clamped down. Returns `nil` for an empty input.

**Parameters:**
- `vectors`: CVSS vector strings to parse
- `workerCount`: number of worker goroutines (clamped to `len(vectors)`)

**Returns:**
- `[]BatchParseResult`: one result per input, in input order

**Type:**

```go
type BatchParseResult struct {
    Index  int          // original input index
    Vector *cvss.Cvss3x // parsed object, nil on failure
    Error  error        // parse error, nil on success
}
```

**Example:**

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
}, 4)
for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: %v", r.Index, r.Error)
        continue
    }
    fmt.Println(r.Vector.String())
}
```

### BatchValidate

```go
func BatchValidate(vectors []string, workerCount int) []BatchValidateResult
```

Concurrently parses **and** validates each vector in one step (uses `ParseAndValidate` internally). Each result carries both the parsed vector and a slice of validation error messages. Same worker-count clamping rules as `BatchParse`.

**Parameters:**
- `vectors`: CVSS vector strings to parse and validate
- `workerCount`: number of worker goroutines

**Returns:**
- `[]BatchValidateResult`: one result per input, in input order

**Type:**

```go
type BatchValidateResult struct {
    Index  int          // original input index
    Vector *cvss.Cvss3x // parsed object, nil on failure
    Valid  bool         // whether the vector is valid
    Errors []string     // all validation error messages
    Error  error        // parse error (distinct from validation errors)
}
```

**Example:**

```go
results := parser.BatchValidate(myVectors, runtime.NumCPU())
valid := 0
for _, r := range results {
    if r.Valid {
        valid++
        continue
    }
    log.Printf("index %d invalid: %v", r.Index, r.Errors)
}
fmt.Printf("%d/%d valid\n", valid, len(results))
```

## One-Shot Convenience Functions

For single vectors, the convenience functions in `pkg/parser` collapse common multi-step flows into one call. Each is a thin wrapper around `NewCvss3xParser` + `Parse`:

| Function | Returns | Use when |
| -------- | ------- | -------- |
| `ParseString(str)` | `(*Cvss3x, error)` | You just need the parsed struct |
| `MustParse(str)` | `*Cvss3x` (panics on error) | Tests / hardcoded vectors |
| `ParseRelaxed(str, defaultVer)` | `(*Cvss3x, error)` | Input may lack the `CVSS:` prefix |
| `ParseAndValidate(str)` | `(*Cvss3x, error)` | You need structural validation errors |
| `ParseAndScore(str)` | `(*Cvss3x, float64, Severity, error)` | You want parse → validate → score in one call |

Prefer `ParseAndScore` for the common "give me the score for this vector" path — it avoids constructing a separate `Calculator` by hand.

## Concurrent Processing Patterns

When the batch helpers don't fit (e.g. you need to score in parallel, or fan out work across a pipeline), the idiomatic pattern is a worker pool over a buffered channel. Because each `*Cvss3x` is read-only after parse, a parsed vector can be handed to many scoring goroutines safely:

```go
func scoreConcurrently(vectors []string, workers int) ([]float64, error) {
    type job struct{ idx int; vec string }
    type result struct{ idx int; score float64; err error }

    jobs := make(chan job, len(vectors))
    results := make([]float64, len(vectors))

    // Producer
    go func() {
        for i, v := range vectors {
            jobs <- job{i, v}
        }
        close(jobs)
    }()

    // Workers — each parses and scores its own inputs
    var wg sync.WaitGroup
    for w := 0; w < workers; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := range jobs {
                cv, err := parser.ParseString(j.vec)
                if err != nil {
                    // surface error as appropriate; here we store 0
                    continue
                }
                score, err := cvss.NewCalculator(cv).Calculate()
                if err == nil {
                    results[j.idx] = score
                }
            }
        }()
    }
    wg.Wait()
    return results, nil
}
```

::: warning Do not share a `Calculator` or `Cvss3xParser` across goroutines
A `Calculator` is bound to one `*Cvss3x` at construction and a `Cvss3xParser` to one input string. Both are meant to be short-lived and single-goroutine. The parsed `*Cvss3x` is the only object safe to share — construct a fresh `Calculator` per goroutine with `cvss.NewCalculator(cv)`.
:::

## Benchmarking

Use the Go standard library's `testing.B` for benchmarks — there is no in-library benchmarker. Place benchmarks in a `_test.go` file:

```go
func BenchmarkParseString(b *testing.B) {
    vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, _ = parser.ParseString(vector)
    }
}

func BenchmarkCalculate(b *testing.B) {
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = cvss.NewCalculator(cv).Calculate()
    }
}
```

Run with:

```bash
go test -bench=. -benchmem ./...
```

For CPU and memory profiling, use `runtime/pprof` (or the `-cpuprofile` / `-memprofile` flags of `go test`):

```bash
go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./...
go tool pprof cpu.prof
go tool pprof mem.prof
```

## Best Practices

### Memory

1. **Don't pool parsers/calculators** — they bind input at construction and cannot rebound; just construct per call.
2. **Reuse the parsed `*Cvss3x`** — it is immutable after parse; cache it if the same vector is scored repeatedly.
3. **Use `b.ReportAllocs()`** in benchmarks to track allocation pressure.
4. **Batch large inputs** — `BatchParse` / `BatchValidate` avoid per-item goroutine setup overhead versus ad-hoc worker pools.

### Concurrency

1. **Pick a sensible worker count** — `runtime.NumCPU()` is a good default for CPU-bound scoring.
2. **Buffer the jobs channel** — `make(chan job, len(inputs))` prevents the producer from blocking.
3. **Preserve input order** — write results by index, as `BatchParse` does, rather than appending.
4. **Share `*Cvss3x`, not `Calculator`** — the parsed struct is read-only and concurrency-safe; calculators are not.

### Caching

1. **Cache the parsed vector, not the parser** — the `*Cvss3x` is immutable and cheap to hold.
2. **Key on the normalized vector string** — `cvss3x.String()` returns the canonical form; use it as the cache key.
3. **Bound the cache** — an unbounded map grows forever; use an LRU (your application's choice of library).
4. **Invalidate on version change** — a `CVSS:3.0` and `CVSS:3.1` vector with the same metrics can score differently; include the version prefix in the cache key.

## Examples

### Batch scoring with BatchParse

```go
vectors := loadVectorsFromFile("vectors.txt") // []string, one per line
results := parser.BatchParse(vectors, runtime.NumCPU())

for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: parse failed: %v", r.Index, r.Error)
        continue
    }
    score, err := cvss.NewCalculator(r.Vector).Calculate()
    if err != nil {
        log.Printf("index %d: score failed: %v", r.Index, err)
        continue
    }
    fmt.Printf("%s -> %.1f\n", r.Vector.String(), score)
}
```

### Caching parsed vectors

```go
// Application-level LRU cache; the library does not provide one.
var cache = lru.New(capacity) // from your chosen LRU library

func scoreCached(vectorStr string) (float64, error) {
    if cv, ok := cache.Get(vectorStr); ok {
        return cvss.NewCalculator(cv.(*cvss.Cvss3x)).Calculate()
    }
    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        return 0, err
    }
    cache.Add(vectorStr, cv)
    return cvss.NewCalculator(cv).Calculate()
}
```

## Related Documentation

- [Performance Examples](/examples/performance) - Practical optimization walkthroughs
- [Calculator API](/api/cvss/calculator) - The scoring API bound at construction
- [Parser API](/api/parser/) - `ParseString`, `BatchParse`, and the convenience functions
