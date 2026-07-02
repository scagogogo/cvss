# parser Package

The `parser` package parses CVSS vector strings into structured objects. It supports CVSS 3.0 and 3.1; the input string is bound at construction time and the parser is consumed once.

## Package Overview

```go
import "github.com/scagogogo/cvss-skills/pkg/parser"
```

## Main Types

### Parsers

| Type | Description | Documentation Link |
|------|-------------|-------------------|
| `Cvss3xParser` | CVSS 3.x vector parser (input string bound at construction) | [Detailed Documentation](/api/parser/cvss3x-parser) |
| `VectorParser` | Registry mapping metric name/value to `vector.Vector` (a struct, not an interface) | — |

::: tip No Parser interface
This package exposes no generic `Parser` interface, and `VectorParser` is a struct rather than an interface. `Cvss3xParser` is the entry point for CVSS 3.x vector strings.
:::

## Quick Start

### Basic Parsing

```go
vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
p := parser.NewCvss3xParser(vectorStr)

vector, err := p.Parse()
if err != nil {
    log.Fatalf("parse failed: %v", err)
}

fmt.Printf("parse successful: %s\n", vector.String())
```

### Convenience Functions

The `parser` package provides one-liners; each constructs a fresh parser internally:

| Function | Signature | Behavior |
|----------|-----------|----------|
| `ParseString` | `(str string) (*cvss.Cvss3x, error)` | `NewCvss3xParser(str).Parse()` |
| `MustParse` | `(str string) *cvss.Cvss3x` | Same as `ParseString`, but panics on error |
| `ParseRelaxed` | `(str, defaultVersion string) (*cvss.Cvss3x, error)` | Accepts strings without the `CVSS:3.1/` prefix; prepends `CVSS:<defaultVersion>/` (default `"3.1"`) |
| `ParseAndValidate` | `(str string) (*cvss.Cvss3x, error)` | Parses then runs `Validate()`; fails if base metrics are missing |
| `ParseAndScore` | `(str string) (*cvss.Cvss3x, float64, cvss.Severity, error)` | Parses and computes the base score plus severity |

### Batch Parsing

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
    "not-a-vector",
}, 4)

for _, r := range results {
    if r.Error != nil {
        fmt.Printf("index %d failed: %v\n", r.Index, r.Error)
        continue
    }
    fmt.Printf("index %d ok: %s\n", r.Index, r.Vector.String())
}
```

## Parsing Flow

```mermaid
flowchart TD
    In["CVSS:3.1/AV:N/AC:L/..."] --> Head{"starts with 'CVSS:'?"}
    Head -->|No| Err1["ErrParserMagicHead"]
    Head -->|Yes| Ver{version 3.0 / 3.1?}
    Ver -->|No| ErrV["fmt.Errorf:<br/>unsupported version"]
    Ver -->|Yes| Loop
    Loop["for each /KEY:VALUE"] --> Dup{KEY seen before?}
    Dup -->|Yes| ErrD["ErrDuplicateMetric"]
    Dup -->|No| Known{GetVectorByShortName<br/>recognizes KEY:VALUE?}
    Known -->|No| Err2["fmt.Errorf:<br/>unknown/illegal value"]
    Known -->|Yes| Set["set metric"]
    Set --> Loop
    Loop -->|done| Out(["*cvss.Cvss3x"])
    Out --> Check{Check() / Validate()}
    Check -->|missing base metric| Err3["cvss.ValidationErrors<br/>MissingMetrics()"]

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class Err1,ErrV,ErrD,Err2,Err3 err;
```

::: warning Parse does not enforce completeness
`Parse()` returns a `*Cvss3x` even when base metrics are missing. To require the base metrics, call `Check()` (returns the first missing metric) or `Validate()` (returns `cvss.ValidationErrors` listing all missing metrics) after parsing.
:::

## Error Handling

### Sentinel Errors

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
    // otherwise a fmt.Errorf describing an unsupported version, unknown metric name, or illegal value
    log.Fatal(err)
}
```

### Post-Parse Validation Errors

Completeness is checked by the `cvss` package, not the parser:

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

::: tip No positional ParseError
This package does not return a `*parser.ParseError` carrying `Position`/`Input` fields. Every parse error is either one of the sentinels above or a plain `fmt.Errorf` with a text message.
:::

## Supported Formats

### Standard Format

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

### Full Vector

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
```

## Performance

### Concurrent Parsing

`Cvss3xParser` holds mutable cursor state and must **not** be shared across goroutines. Construct a fresh parser per vector (or just use `BatchParse`):

```go
func parseVectorsConcurrently(vectors []string) []*cvss.Cvss3x {
    results := make([]*cvss.Cvss3x, len(vectors))
    var wg sync.WaitGroup

    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, s string) {
            defer wg.Done()
            cv, err := parser.ParseString(s) // each goroutine uses a new parser
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
Reusing a `*Cvss3xParser` via `sync.Pool` together with a non-existent `SetVector` to reset the input string is unsupported — the input string is fixed at construction. Pooling plain strings and calling `ParseString` is fine; pooling parser objects is not.
:::

## Best Practices

### 1. Error Handling

```go
func safeParseVector(vectorStr string) (*cvss.Cvss3x, error) {
    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        return nil, fmt.Errorf("parse vector failed '%s': %w", vectorStr, err)
    }

    // additionally validate completeness
    if err := cv.Check(); err != nil {
        return nil, fmt.Errorf("vector validation failed: %w", err)
    }

    return cv, nil
}
```

### 2. Input Validation

```go
func validateInput(vectorStr string) error {
    if vectorStr == "" {
        return fmt.Errorf("vector string must not be empty")
    }

    if len(vectorStr) > 1000 {
        return fmt.Errorf("vector string too long")
    }

    if !strings.HasPrefix(strings.ToUpper(vectorStr), "CVSS:") {
        // ParseRelaxed can handle prefix-less input; otherwise treat as an error
        return fmt.Errorf("invalid vector format (missing 'CVSS:' prefix)")
    }

    return nil
}
```

## Related Documentation

- [Cvss3xParser detailed documentation](/api/parser/cvss3x-parser)
- [Cvss3x data structure](/api/cvss/cvss3x)
- [Usage examples](/examples/parsing)
- [Error handling guide](/api/cvss/)
