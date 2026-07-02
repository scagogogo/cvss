# API Reference

CVSS Skills provides a complete set of Go language APIs for parsing, calculating, and processing CVSS (Common Vulnerability Scoring System) vectors.

## Package Structure

CVSS Skills contains three main packages. `parser` turns strings into `vector`-typed structs, and `cvss` operates on them:

```mermaid
flowchart LR
    subgraph parser["📦 pkg/parser"]
        P["Cvss3xParser"]
        VP["VectorParser (interface)"]
    end
    subgraph vector["📦 pkg/vector"]
        VI["Vector (interface)"]
        BM["Base / Temporal /<br/>Environmental metrics"]
    end
    subgraph cvss["📦 pkg/cvss"]
        C3["Cvss3x"]
        Calc["Calculator"]
        Dist["DistanceCalculator"]
    end

    Str["vector string"] --> P
    P -->|produces| C3
    C3 -->|implements| VI
    VI --> BM
    C3 --> Calc
    C3 --> Dist
    Calc --> Score(["score + severity"])
    Dist --> D(["distance metrics"])

    classDef pkg fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    class P,VP,VI,BM,C3,Calc,Dist pkg;
```

### 📦 [cvss](/api/cvss/)
Core package containing CVSS data structures, score calculators, and distance calculation functionality.

**Main Types:**
- `Cvss3x` - CVSS 3.x vector representation
- `Calculator` - CVSS score calculator
- `DistanceCalculator` - Vector distance calculator

### 📦 [parser](/api/parser/)
Parsing package responsible for parsing CVSS vector strings into structured data.

**Main Types:**
- `Cvss3xParser` - CVSS 3.x vector string parser
- `VectorParser` - Generic vector parser interface

### 📦 [vector](/api/vector/)
Vector package providing unified interfaces and implementations for all CVSS metrics.

**Main Types:**
- `Vector` - Unified interface for all metrics
- Specific implementations for base, temporal, and environmental metrics

## Quick Navigation

### 🚀 Getting Started
- [5-Minute Quick Start](/api/getting-started) - Fastest way to get started
- [Basic Examples](/examples/basic) - Simple usage examples

### 📚 Core Packages
- [CVSS Package Guide](/api/cvss/) - Core functionality introduction
- [Parser Usage](/api/parser/) - String parsing
- [Vector Analysis](/api/vector/) - Metric interfaces

### 💡 Practical Examples
- [JSON Processing](/examples/json) - Data serialization
- [Batch Processing](/examples/parsing) - Batch vector parsing
- [Similarity Analysis](/examples/distance) - Vector comparison

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Parse CVSS vector
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }

    // Calculate score
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("Calculation failed: %v", err)
    }

    fmt.Printf("CVSS Score: %.1f\n", score)
    fmt.Printf("Severity: %s\n", calculator.GetSeverityRating(score))
}
```

### Advanced Features

```go
// Vector comparison
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
distance := distCalc.EuclideanDistance()

// JSON serialization
jsonData, err := json.Marshal(vector)
```

## API Design Principles

### 🎯 Type Safety

APIs use concrete types, not interfaces-for-configurability. `Calculator` is a struct constructed with the vector to score:

```go
type Calculator struct { /* unexported: holds the *Cvss3x */ }

func NewCalculator(cvss *Cvss3x) *Calculator
func (c *Calculator) Calculate() (float64, error)
func (c *Calculator) GetSeverityRating(score float64) Severity // Severity is a named string type
```

### 🔧 Convenience Functions

One-shot helpers avoid manual multi-step setup; the parser binds its string at construction (there is no strict/relaxed toggle or `SetVector`):

```go
// Parse + score in one call
cv, score, severity, err := parser.ParseAndScore(vectorStr)

// Accept input without the CVSS:3.1/ prefix
cv, err := parser.ParseRelaxed(vectorStr, "3.1")
```

### 📊 Rich Error Information

Parse errors are sentinels (`ErrParserMagicHead`, `ErrDuplicateMetric`) or `fmt.Errorf`; validation errors come from the `cvss` package as `ValidationErrors`:

```go
if err != nil {
    if errors.Is(err, parser.ErrParserMagicHead) {
        log.Printf("not a CVSS vector: %v", err)
    }
}
if err := cv.Validate(); err != nil {
    if ve, ok := err.(cvss.ValidationErrors); ok {
        for _, m := range ve.MissingMetrics() {
            fmt.Printf("missing metric: %s\n", m)
        }
    }
}
```

## Performance Characteristics

### ⚡ High Performance

- Zero-allocation parser design
- Optimized calculation algorithms
- Memory-friendly data structures

### 📈 Scalability

- Support for batch processing
- Concurrent-safe design
- Pluggable component architecture

## Version Compatibility

| CVSS Skills Version | CVSS Specification Support | Go Version Requirement |
|---------------------|----------------------------|------------------------|
| v1.x | CVSS 3.0, 3.1 | Go 1.19+ |
| v2.x | CVSS 3.0, 3.1, 4.0 | Go 1.21+ |

## Best Practices

### 🛡️ Error Handling

Always check errors and provide appropriate handling:

```go
vector, err := parser.ParseString(vectorStr)
if err != nil {
    log.Printf("Parse failed: %v", err)
    return
}
```

### 🔄 Resource Management

For large data processing, consider using object pools:

```go
var parserPool = sync.Pool{
    New: func() interface{} {
        return parser.NewCvss3xParser("")
    },
}
```

### 📊 Performance Monitoring

Use built-in performance metrics:

```go
start := time.Now()
score, err := calculator.Calculate()
duration := time.Since(start)
log.Printf("Calculation took: %v", duration)
```

## Next Steps

- **[Getting Started](/api/getting-started)** - 5-minute quick start guide
- **[CVSS Package Deep Dive](/api/cvss/)** - Core functionality overview
- **[Example Code](/examples/)** - Practical usage examples
- **[Best Practices](/api/getting-started)** - Production environment recommendations

## Getting Help

If you encounter issues while using the API:

1. Check the [FAQ](/api/getting-started)
2. Browse [Example Code](/examples/)
3. Submit issues on [GitHub](https://github.com/scagogogo/cvss-skills/issues)
4. Join [Community Discussions](https://github.com/scagogogo/cvss-skills/discussions)