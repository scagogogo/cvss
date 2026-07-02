# Getting Started

This guide will help you get started with CVSS Skills in 5 minutes.

## The 3-Step Mental Model

Almost every program follows the same three steps: **parse → calculate → interpret**.

```mermaid
flowchart LR
    A["1 · Parse<br/>NewCvss3xParser().Parse()"] --> B["2 · Calculate<br/>NewCalculator().Calculate()"]
    B --> C["3 · Interpret<br/>GetSeverityRating(score)"]
    C --> R(["9.8 → Critical"])

    classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    class A,B,C step;
```

## Installation

Install CVSS Skills using Go modules:

```bash
go get github.com/scagogogo/cvss-skills
```

## Your First Program

Create a new Go file `main.go`:

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 1. Create parser
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    p := parser.NewCvss3xParser(vectorStr)

    // 2. Parse CVSS vector
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }

    // 3. Create calculator
    calculator := cvss.NewCalculator(cvssVector)

    // 4. Calculate score
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("Calculation failed: %v", err)
    }

    // 5. Get severity rating
    severity := calculator.GetSeverityRating(score)

    // 6. Output results
    fmt.Printf("CVSS Vector: %s\n", vectorStr)
    fmt.Printf("Base Score: %.1f\n", score)
    fmt.Printf("Severity: %s\n", severity)
}
```

Run the program:

```bash
go run main.go
```

Output:
```
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base Score: 9.8
Severity: Critical
```

## Core Concepts

### 1. CVSS Vector

A CVSS vector is a string describing vulnerability characteristics:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

- `CVSS:3.1` - Version identifier
- `AV:N` - Attack Vector: Network
- `AC:L` - Attack Complexity: Low
- `PR:N` - Privileges Required: None
- `UI:N` - User Interaction: None
- `S:U` - Scope: Unchanged
- `C:H` - Confidentiality Impact: High
- `I:H` - Integrity Impact: High
- `A:H` - Availability Impact: High

### 2. Parser

The parser converts CVSS vector strings into structured objects:

```go
// Create parser
parser := parser.NewCvss3xParser(vectorString)

// Parse vector
cvssVector, err := parser.Parse()
```

### 3. Calculator

The calculator computes CVSS scores based on parsed vectors:

```go
// Create calculator
calculator := cvss.NewCalculator(cvssVector)

// Calculate score
score, err := calculator.Calculate()
```

## Common Features

### Parse Different Vector Types

```go
// Base vector
basic := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

// Vector with temporal metrics
temporal := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"

// Vector with environmental metrics
environmental := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"

vectors := []string{basic, temporal, environmental}

for _, vectorStr := range vectors {
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Printf("Parse failed %s: %v", vectorStr, err)
        continue
    }
    
    calculator := cvss.NewCalculator(vector)
    score, _ := calculator.Calculate()
    
    fmt.Printf("Vector: %s\n", vectorStr)
    fmt.Printf("Score: %.1f\n", score)
    fmt.Printf("Severity: %s\n\n", calculator.GetSeverityRating(score))
}
```

### Get Detailed Information

```go
// Get vector details
fmt.Printf("CVSS Version: %d.%d\n", cvssVector.MajorVersion, cvssVector.MinorVersion)
fmt.Printf("Attack Vector: %s\n", cvssVector.Cvss3xBase.AttackVector.GetLongValue())
fmt.Printf("Attack Complexity: %s\n", cvssVector.Cvss3xBase.AttackComplexity.GetLongValue())
```

### Vector Comparison

```go
// Parse two vectors
vector1, _ := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").Parse()
vector2, _ := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L").Parse()

// Calculate distance
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
distance := distCalc.EuclideanDistance()

fmt.Printf("Vector distance: %.3f\n", distance)
```

### JSON Serialization

```go
import "encoding/json"

// Serialize to JSON
jsonData, err := json.MarshalIndent(cvssVector, "", "  ")
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))

// Deserialize from JSON
var newVector cvss.Cvss3x
err = json.Unmarshal(jsonData, &newVector)
if err != nil {
    log.Fatal(err)
}
```

## Error Handling

CVSS Skills surfaces parse errors as sentinels or `fmt.Errorf`, and validation errors as `cvss.ValidationErrors`:

```go
cv, err := parser.ParseString(vectorStr)
if err != nil {
    if errors.Is(err, parser.ErrParserMagicHead) {
        fmt.Printf("Not a CVSS vector (missing 'CVSS:' prefix)\n")
    }
    log.Fatal(err)
}

// Completeness is checked separately from parsing
if err := cv.Validate(); err != nil {
    if ve, ok := err.(cvss.ValidationErrors); ok {
        for _, m := range ve.MissingMetrics() {
            fmt.Printf("Missing metric: %s\n", m)
        }
    }
}
```

## Severity Levels

CVSS scores correspond to severity levels:

| Score Range | Severity Level | Description |
|-------------|----------------|-------------|
| 0.0 | None | No impact |
| 0.1-3.9 | Low | Low risk |
| 4.0-6.9 | Medium | Medium risk |
| 7.0-8.9 | High | High risk |
| 9.0-10.0 | Critical | Critical risk |

```go
score := 7.5
severity := calculator.GetSeverityRating(score)
fmt.Printf("Score %.1f corresponds to severity: %s\n", score, severity) // High
```

## Performance Tips

### 1. Use the Convenience Function

`Cvss3xParser` binds its input string at construction and is not reusable — there is no `SetVector`. For one-shot parsing, use `parser.ParseString`, which constructs a fresh parser each call:

```go
// Good practice: one-shot parse per vector
for _, vectorStr := range vectors {
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        continue
    }
    // Process vector...
}
```

### 2. Batch Processing

```go
func processBatch(vectors []string) []float64 {
    results := make([]float64, len(vectors))
    
    for i, vectorStr := range vectors {
        p := parser.NewCvss3xParser(vectorStr)
        vector, err := p.Parse()
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            continue
        }
        
        results[i] = score
    }
    
    return results
}
```

## Next Steps

Now that you've mastered the basics, you can continue learning:

1. **[Detailed API Documentation](/api/)** - Learn about all available APIs
2. **[Example Code](/examples/)** - See more practical usage examples
3. **[CVSS Package Deep Dive](/api/cvss/)** - Understand core functionality
4. **[Best Practices](/api/getting-started)** - Production environment recommendations

## Getting Help

If you encounter issues:

- Check the [FAQ](/api/getting-started)
- Browse [GitHub Issues](https://github.com/scagogogo/cvss-skills/issues)
- Join [Community Discussions](https://github.com/scagogogo/cvss-skills/discussions)
