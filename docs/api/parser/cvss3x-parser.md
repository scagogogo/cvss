# Cvss3xParser - CVSS 3.x Parser

`Cvss3xParser` is a specialized parser for CVSS 3.x vector strings. The string is supplied at construction time and the parser is consumed once via `Parse()`.

## Parsing Flow

Parsing reads the `CVSS:` magic head, the version, then walks each `/KEY:VALUE` segment. Unknown metric names and illegal values surface as errors; the parser does not silently drop them:

```mermaid
flowchart TD
    In["CVSS:3.1/AV:N/AC:L/..."] --> Head{"starts with<br/>'CVSS:'?"}
    Head -->|No| Err1["ErrParserMagicHead"]
    Head -->|Yes| Ver{version 3.0 / 3.1?}
    Ver -->|No| ErrV["fmt.Errorf:<br/>unsupported version"]
    Ver -->|Yes| Loop
    Loop["for each /KEY:VALUE"] --> Dup{seen KEY?}
    Dup -->|Yes| ErrD["ErrDuplicateMetric"]
    Dup -->|No| Known{GetVectorByShortName<br/>knows KEY:VALUE?}
    Known -->|No| Err2["fmt.Errorf:<br/>unknown/illegal value"]
    Known -->|Yes| Set["set metric on Cvss3x"]
    Set --> Loop
    Loop -->|done| Out(["*cvss.Cvss3x"])
    Out --> Check{Check() / Validate()}
    Check -->|missing base| Err3["cvss.ValidationErrors<br/>MissingMetrics()"]

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class Err1,ErrV,ErrD,Err2,Err3 err;
```

Note that `Parse()` itself does **not** enforce completeness — it returns a `*Cvss3x` even if base metrics are missing. Call `Check()` (first missing metric) or `Validate()` (all of them, as `cvss.ValidationErrors`) afterwards to enforce the required base metrics.

## Type Definition

`Cvss3xParser` holds the input string and parse cursor. Its fields are unexported; you construct it with `NewCvss3xParser` and call `Parse`:

```go
type Cvss3xParser struct {
    // unexported: input string, rune cursor, parsed-key set, result *cvss.Cvss3x
}

func NewCvss3xParser(cvss3xStr string) *Cvss3xParser
func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

## Creating a Parser

### NewCvss3xParser

```go
func NewCvss3xParser(cvss3xStr string) *Cvss3xParser
```

Creates a new CVSS 3.x parser bound to the given vector string. The string is trimmed of surrounding whitespace.

**Parameters:**
- `cvss3xStr`: The CVSS vector string to parse

**Returns:**
- `*Cvss3xParser`: Parser instance

**Example:**
```go
p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

::: warning There is no SetVector — parsers are not reusable
The vector string is fixed at construction. There is no `SetVector` method to rebind a parser to a new string. To parse another vector, construct a new parser (they are cheap) or use the `parser.ParseString` convenience function.
:::

## Main Method

### Parse

```go
func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

Parses the bound vector string and returns a structured `*cvss.Cvss3x`. Returns an error for an invalid magic head, unsupported version, duplicate metric key, unknown metric name, or illegal metric value.

**Returns:**
- `*cvss.Cvss3x`: The parsed CVSS vector object (always non-nil on nil error)
- `error`: Parse error — a sentinel (`ErrParserMagicHead`, `ErrDuplicateMetric`) or a `fmt.Errorf` describing the problem

**Example:**
```go
vector, err := p.Parse()
if err != nil {
    log.Fatalf("Parse failed: %v", err)
}
fmt.Printf("Parse successful: %s\n", vector.String())
```

## Convenience Functions

The `parser` package provides one-shot helpers that construct a parser, parse, and (for some) validate or score in a single call:

| Function | Signature | Behavior |
|----------|-----------|----------|
| `ParseString` | `(str string) (*cvss.Cvss3x, error)` | `NewCvss3xParser(str).Parse()` |
| `MustParse` | `(str string) *cvss.Cvss3x` | like `ParseString` but panics on error |
| `ParseRelaxed` | `(str, defaultVersion string) (*cvss.Cvss3x, error)` | accepts a string without the `CVSS:3.1/` prefix; prepends `CVSS:<defaultVersion>/` (defaults to `"3.1"`) |
| `ParseAndValidate` | `(str string) (*cvss.Cvss3x, error)` | parse, then `Validate()` — fails if base metrics are missing |
| `ParseAndScore` | `(str string) (*cvss.Cvss3x, float64, cvss.Severity, error)` | parse, then calculate base score and severity |

```go
// One-liner
cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// No-prefix input
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")

// Parse + validate (rejects incomplete vectors)
cv, err := parser.ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// Parse + score
cv, score, severity, err := parser.ParseAndScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## Error Handling

`Parse` returns one of two kinds of error:

### Sentinel errors

```go
var ErrParserMagicHead = errors.New("cvss 3.x parser error: invalid magic head, it must equal 'CVSS'")
var ErrDuplicateMetric = errors.New("cvss 3.x parser error: duplicate metric key")
```

Detect them with `errors.Is`:

```go
vector, err := p.Parse()
if err != nil {
    if errors.Is(err, parser.ErrParserMagicHead) {
        log.Fatal("input is not a CVSS vector (missing 'CVSS:' prefix)")
    }
    if errors.Is(err, parser.ErrDuplicateMetric) {
        log.Fatalf("duplicate metric: %v", err)
    }
    // otherwise a fmt.Errorf describing an unsupported version,
    // unknown metric name, or illegal metric value
    log.Fatal(err)
}
```

### Validation errors (after parsing)

Completeness is checked separately via the `cvss` package, not the parser:

```go
cv, err := parser.ParseString(vectorStr)
if err != nil {
    return err
}
if err := cv.Validate(); err != nil {
    if ve, ok := err.(cvss.ValidationErrors); ok {
        for _, m := range ve.MissingMetrics() {
            fmt.Printf("missing metric: %s\n", m)
        }
    }
}
```

## Batch Operations

For parsing many vectors concurrently, use the package-level batch helpers:

```go
type BatchParseResult struct {
    Index  int          // original input index
    Vector *cvss.Cvss3x // nil on error
    Error  error        // nil on success
}

func BatchParse(vectors []string, workerCount int) []BatchParseResult

type BatchValidateResult struct {
    Index  int
    Vector *cvss.Cvss3x
    Valid  bool
    Errors []string
    Error  error
}

func BatchValidate(vectors []string, workerCount int) []BatchValidateResult
```

`workerCount <= 0` uses `len(vectors)` workers. Results are returned in input order.

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
    "not-a-vector",
}, 4)
for _, r := range results {
    if r.Error != nil {
        fmt.Printf("index %d failed: %v\n", r.Index, r.Error)
        continue
    }
    fmt.Printf("index %d: %s\n", r.Index, r.Vector.String())
}
```

## Supported Vector Formats

### CVSS 3.0 / 3.1

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### With Temporal Metrics

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
```

### With Environmental Metrics

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L
```

## Usage Examples

### Basic Parsing

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }

    fmt.Printf("Original vector: %s\n", vectorStr)
    fmt.Printf("Parsed result:   %s\n", vector.String())
    fmt.Printf("Version:         %d.%d\n", vector.MajorVersion, vector.MinorVersion)
}
```

### Parsing a Batch

```go
func parseBatch(vectors []string) {
    results := parser.BatchParse(vectors, 4)
    for _, r := range results {
        if r.Error != nil {
            fmt.Printf("Vector %d parse failed: %v\n", r.Index+1, r.Error)
            continue
        }
        fmt.Printf("Vector %d: %s -> OK\n", r.Index+1, r.Vector.String())
    }
}
```

### Tolerant Parsing (no prefix)

Use `ParseRelaxed` when the input may lack the `CVSS:3.1/` prefix:

```go
// Accepts "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" — assumes 3.1
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
if err != nil {
    log.Fatal(err)
}
fmt.Println(cv.String()) // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Parse-and-Validate (reject incomplete vectors)

```go
cv, err := parser.ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
if err != nil {
    // either a parse error, or a cvss.ValidationErrors listing missing metrics
    log.Fatal(err)
}
fmt.Println(cv.String())
```

## Performance Optimization

### Concurrent Parsing

`Cvss3xParser` holds mutable cursor state, so one parser must not be shared across goroutines. Construct a fresh parser per vector (or use `BatchParse`, which does this for you):

```go
func parseVectorsConcurrently(vectors []string) []*cvss.Cvss3x {
    results := make([]*cvss.Cvss3x, len(vectors))
    var wg sync.WaitGroup

    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, s string) {
            defer wg.Done()
            cv, err := parser.ParseString(s) // fresh parser per goroutine
            if err != nil {
                results[index] = nil
                return
            }
            results[index] = cv
        }(i, vectorStr)
    }

    wg.Wait()
    return results
}
```

::: warning Do not pool parsers
A `sync.Pool` of `*Cvss3xParser` reusing a single instance via a non-existent `SetVector` is not supported — the input string is fixed at construction. Pooling plain strings and calling `ParseString` is fine; pooling parser objects is not.
:::

## Best Practices

### 1. Input Validation

```go
func validateInput(vectorStr string) error {
    if vectorStr == "" {
        return fmt.Errorf("vector string cannot be empty")
    }
    if len(vectorStr) > 1000 {
        return fmt.Errorf("vector string too long")
    }
    if !strings.HasPrefix(strings.ToUpper(vectorStr), "CVSS:") {
        // ParseRelaxed can handle prefix-less input; otherwise this is an error
        return fmt.Errorf("invalid vector format (missing 'CVSS:' prefix)")
    }
    return nil
}
```

### 2. Logging

```go
func parseWithLogging(vectorStr string) (*cvss.Cvss3x, error) {
    start := time.Now()
    defer func() {
        log.Printf("Parse took: %v", time.Since(start))
    }()

    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        log.Printf("Parse failed '%s': %v", vectorStr, err)
        return nil, err
    }
    log.Printf("Parse successful '%s'", vectorStr)
    return cv, nil
}
```

## Related Documentation

- [parser Package Overview](/api/parser/)
- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Error Handling Guide](/api/error-handling)
- [Parsing Examples](/examples/parsing)
