# Vector Parsing Examples

This example demonstrates various ways to parse CVSS vector strings, including different formats, error handling, and validation techniques.

## Overview

CVSS Skills supports parsing CVSS 3.0 and 3.1 vector strings in various formats and configurations. This guide covers:

- Basic vector parsing
- Different vector formats
- Error handling and validation
- Batch parsing
- Performance optimization

## Basic Vector Parsing

### Simple Parsing

```go
package main

import (
    "bufio"
    "errors"
    "fmt"
    "log"
    "os"
    "strings"
    "sync"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Basic CVSS 3.1 vector
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // Create parser
    p := parser.NewCvss3xParser(vectorStr)
    
    // Parse vector
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }
    
    fmt.Printf("Successfully parsed: %s\n", vector.String())
    fmt.Printf("Version: %d.%d\n", vector.MajorVersion, vector.MinorVersion)
}
```

### Parsing Different CVSS Versions

```go
func parseMultipleVersions() {
    vectors := map[string]string{
        "CVSS 3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS 3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    
    for version, vectorStr := range vectors {
        fmt.Printf("\n--- Parsing %s ---\n", version)

        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }

        fmt.Printf("Vector: %s\n", vectorStr)
        fmt.Printf("Parsed Version: %d.%d\n", vector.MajorVersion, vector.MinorVersion)
        fmt.Printf("Complete: %t\n", vector.IsComplete())
    }
}
```

## Vector Format Variations

### Base Metrics Only

```go
func parseBaseOnly() {
    // Minimal required base metrics
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    vector, err := parser.ParseString(baseVector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Base vector: %s\n", vector.String())
    fmt.Printf("Has temporal: %t\n", vector.HasTemporalMetrics())
    fmt.Printf("Has environmental: %t\n", vector.HasEnvironmentalMetrics())
}
```

### Vector with Temporal Metrics

```go
func parseWithTemporal() {
    // Vector with temporal metrics
    temporalVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"

    vector, err := parser.ParseString(temporalVector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Temporal vector: %s\n", vector.String())
    fmt.Printf("Has temporal: %t\n", vector.HasTemporalMetrics())

    if vector.HasTemporalMetrics() {
        fmt.Printf("Exploit Code Maturity: %s\n",
            vector.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue())
        fmt.Printf("Remediation Level: %s\n",
            vector.Cvss3xTemporal.RemediationLevel.GetLongValue())
        fmt.Printf("Report Confidence: %s\n",
            vector.Cvss3xTemporal.ReportConfidence.GetLongValue())
    }
}
```

### Vector with Environmental Metrics

```go
func parseWithEnvironmental() {
    // Vector with environmental metrics
    envVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"

    vector, err := parser.ParseString(envVector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Environmental vector: %s\n", vector.String())
    fmt.Printf("Has environmental: %t\n", vector.HasEnvironmentalMetrics())

    if vector.HasEnvironmentalMetrics() {
        fmt.Printf("Confidentiality Requirement: %s\n",
            vector.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue())
        fmt.Printf("Modified Attack Vector: %s\n",
            vector.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue())
    }
}
```

### Complete Vector with All Metrics

```go
func parseCompleteVector() {
    // Complete vector with base, temporal, and environmental metrics
    completeVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"

    vector, err := parser.ParseString(completeVector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Complete vector: %s\n", vector.String())
    fmt.Printf("Has temporal: %t\n", vector.HasTemporalMetrics())
    fmt.Printf("Has environmental: %t\n", vector.HasEnvironmentalMetrics())
    fmt.Printf("Total metrics: %d\n", countMetrics(vector))
}

func countMetrics(vector *cvss.Cvss3x) int {
    count := 8 // Base metrics
    if vector.HasTemporalMetrics() {
        count += 3 // Temporal metrics
    }
    if vector.HasEnvironmentalMetrics() {
        count += 11 // Environmental metrics
    }
    return count
}
```

## Error Handling and Validation

### Robust Parsing with Error Handling

```go
func robustParsing(vectorStr string) (*cvss.Cvss3x, error) {
    // Input validation
    if vectorStr == "" {
        return nil, fmt.Errorf("vector string cannot be empty")
    }
    
    if len(vectorStr) > 200 {
        return nil, fmt.Errorf("vector string too long: %d characters", len(vectorStr))
    }
    
    if !strings.HasPrefix(vectorStr, "CVSS:") {
        return nil, fmt.Errorf("invalid vector format: must start with 'CVSS:'")
    }
    
    // Parse with error handling
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        return nil, fmt.Errorf("parse failed: %w", err)
    }

    // Post-parse validation (Check returns the first missing/invalid metric)
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("parsed vector is invalid: %w", err)
    }

    return vector, nil
}
```

### Handling Different Error Types

Parse errors are sentinels (`ErrParserMagicHead`, `ErrDuplicateMetric`) or plain `fmt.Errorf`; validation problems come from the `cvss` package as `ValidationErrors`:

```go
func handleParseErrors(vectorStr string) {
    vector, err := parser.ParseString(vectorStr)

    if err != nil {
        if errors.Is(err, parser.ErrParserMagicHead) {
            fmt.Printf("Not a CVSS vector (missing 'CVSS:' prefix): %v\n", err)
        } else if errors.Is(err, parser.ErrDuplicateMetric) {
            fmt.Printf("Duplicate metric: %v\n", err)
        } else {
            fmt.Printf("Parse error: %v\n", err)
        }
        return
    }

    // Completeness is checked separately from parsing
    if err := vector.Validate(); err != nil {
        if ve, ok := err.(cvss.ValidationErrors); ok {
            fmt.Printf("Missing metrics: %v\n", ve.MissingMetrics())
        } else {
            fmt.Printf("Validation error: %v\n", err)
        }
        return
    }

    fmt.Printf("Successfully parsed: %s\n", vector.String())
}
```

### Validation Examples

```go
func validateVector(vector *cvss.Cvss3x) []string {
    var issues []string
    
    // Check version
    if vector.MajorVersion != 3 {
        issues = append(issues, fmt.Sprintf("Unsupported major version: %d", vector.MajorVersion))
    }
    
    if vector.MinorVersion != 0 && vector.MinorVersion != 1 {
        issues = append(issues, fmt.Sprintf("Unsupported minor version: %d", vector.MinorVersion))
    }
    
    // Check base metrics
    if vector.Cvss3xBase == nil {
        issues = append(issues, "Missing base metrics")
    } else {
        if vector.Cvss3xBase.AttackVector == nil {
            issues = append(issues, "Missing attack vector")
        }
        if vector.Cvss3xBase.AttackComplexity == nil {
            issues = append(issues, "Missing attack complexity")
        }
        // ... check other required metrics
    }
    
    return issues
}
```

## Batch Parsing

### Processing Multiple Vectors

```go
func batchParsing(vectors []string) []ParseResult {
    results := make([]ParseResult, len(vectors))
    
    for i, vectorStr := range vectors {
        result := ParseResult{
            Input: vectorStr,
            Index: i,
        }
        
        vector, err := robustParsing(vectorStr)
        if err != nil {
            result.Error = err
        } else {
            result.Vector = vector
            result.Success = true
        }
        
        results[i] = result
    }
    
    return results
}

type ParseResult struct {
    Input   string
    Index   int
    Vector  *cvss.Cvss3x
    Success bool
    Error   error
}

func (r ParseResult) String() string {
    if r.Success {
        return fmt.Sprintf("[%d] SUCCESS: %s", r.Index, r.Input)
    }
    return fmt.Sprintf("[%d] ERROR: %s - %v", r.Index, r.Input, r.Error)
}
```

### Concurrent Batch Processing

```go
func concurrentBatchParsing(vectors []string) []ParseResult {
    results := make([]ParseResult, len(vectors))
    var wg sync.WaitGroup
    
    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, vector string) {
            defer wg.Done()
            
            result := ParseResult{
                Input: vector,
                Index: index,
            }
            
            parsed, err := robustParsing(vector)
            if err != nil {
                result.Error = err
            } else {
                result.Vector = parsed
                result.Success = true
            }
            
            results[index] = result
        }(i, vectorStr)
    }
    
    wg.Wait()
    return results
}
```

### Batch Processing with Statistics

```go
func batchParsingWithStats(vectors []string) BatchStats {
    results := batchParsing(vectors)
    
    stats := BatchStats{
        Total:   len(vectors),
        Results: results,
    }
    
    for _, result := range results {
        if result.Success {
            stats.Successful++
        } else {
            stats.Failed++
            stats.Errors = append(stats.Errors, result.Error)
        }
    }
    
    return stats
}

type BatchStats struct {
    Total      int
    Successful int
    Failed     int
    Results    []ParseResult
    Errors     []error
}

func (s BatchStats) SuccessRate() float64 {
    if s.Total == 0 {
        return 0
    }
    return float64(s.Successful) / float64(s.Total) * 100
}

func (s BatchStats) Print() {
    fmt.Printf("Batch Processing Statistics:\n")
    fmt.Printf("  Total vectors: %d\n", s.Total)
    fmt.Printf("  Successful: %d\n", s.Successful)
    fmt.Printf("  Failed: %d\n", s.Failed)
    fmt.Printf("  Success rate: %.1f%%\n", s.SuccessRate())
    
    if len(s.Errors) > 0 {
        fmt.Printf("  Common errors:\n")
        errorCounts := make(map[string]int)
        for _, err := range s.Errors {
            errorCounts[err.Error()]++
        }
        
        for errMsg, count := range errorCounts {
            fmt.Printf("    %s: %d times\n", errMsg, count)
        }
    }
}
```

## Performance Optimization

### Per-Call Parsing

`Cvss3xParser` binds its input string at construction and cannot be rebound (there is no `SetVector`), so do not try to reuse a parser across vectors. Just call `parser.ParseString` per input — each call constructs a fresh, cheap parser:

```go
func optimizedParsing(vectors []string) []ParseResult {
    results := make([]ParseResult, len(vectors))

    for i, vectorStr := range vectors {
        result := ParseResult{
            Input: vectorStr,
            Index: i,
        }

        vector, err := robustParsing(vectorStr)
        if err != nil {
            result.Error = err
        } else {
            result.Vector = vector
            result.Success = true
        }

        results[i] = result
    }

    return results
}
```

### Concurrent Batch Parsing

For concurrent parsing, give each goroutine its own parser (via `ParseString`); the package also provides `parser.BatchParse` which does this for you:

```go
func pooledBatchParsing(vectors []string) []ParseResult {
    results := make([]ParseResult, len(vectors))
    var wg sync.WaitGroup

    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, vector string) {
            defer wg.Done()

            result := ParseResult{
                Input: vector,
                Index: index,
            }

            parsed, err := robustParsing(vector)
            if err != nil {
                result.Error = err
            } else {
                result.Vector = parsed
                result.Success = true
            }

            results[index] = result
        }(i, vectorStr)
    }

    wg.Wait()
    return results
}
```

## Real-World Examples

### File Processing

```go
func parseVectorsFromFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    lineNum := 0
    
    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())
        
        if line == "" || strings.HasPrefix(line, "#") {
            continue // Skip empty lines and comments
        }
        
        vector, err := robustParsing(line)
        if err != nil {
            fmt.Printf("Line %d error: %v\n", lineNum, err)
            continue
        }
        
        fmt.Printf("Line %d: %s -> Valid\n", lineNum, vector.String())
    }
    
    return scanner.Err()
}
```

### CSV Processing

```go
func parseVectorsFromCSV(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    reader := csv.NewReader(file)
    records, err := reader.ReadAll()
    if err != nil {
        return err
    }
    
    for i, record := range records {
        if i == 0 {
            continue // Skip header
        }
        
        if len(record) < 1 {
            continue
        }
        
        vectorStr := record[0]
        vector, err := robustParsing(vectorStr)
        if err != nil {
            fmt.Printf("Row %d error: %v\n", i+1, err)
            continue
        }
        
        fmt.Printf("Row %d: %s -> Valid\n", i+1, vector.String())
    }
    
    return nil
}
```

## Testing and Validation

### Test Cases

```go
func runParsingTests() {
    testCases := []struct {
        name        string
        vector      string
        expectError bool
        description string
    }{
        {
            name:        "Valid basic vector",
            vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: false,
            description: "Standard high-severity vector",
        },
        {
            name:        "Valid temporal vector",
            vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
            expectError: false,
            description: "Vector with temporal metrics",
        },
        {
            name:        "Invalid version",
            vector:      "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: true,
            description: "Unsupported CVSS version",
        },
        {
            name:        "Missing metrics",
            vector:      "CVSS:3.1/AV:N/AC:L",
            expectError: true,
            description: "Incomplete base metrics",
        },
        {
            name:        "Invalid metric value",
            vector:      "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: true,
            description: "Invalid attack vector value",
        },
    }
    
    for _, tc := range testCases {
        fmt.Printf("\n--- Test: %s ---\n", tc.name)
        fmt.Printf("Description: %s\n", tc.description)
        fmt.Printf("Vector: %s\n", tc.vector)
        
        vector, err := robustParsing(tc.vector)
        
        if tc.expectError {
            if err != nil {
                fmt.Printf("✓ Expected error: %v\n", err)
            } else {
                fmt.Printf("✗ Expected error but parsing succeeded\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ Unexpected error: %v\n", err)
            } else {
                fmt.Printf("✓ Parsing succeeded: %s\n", vector.String())
            }
        }
    }
}
```

## Next Steps

After mastering vector parsing, you can explore:

- [JSON Output](/examples/json) - Serializing parsed vectors
- [Distance Calculation](/examples/distance) - Comparing vectors
- [Advanced Examples](/examples/edge-cases) - Complex scenarios

## Related Documentation

- [Parser API Reference](/api/parser/) - Detailed parser documentation
- [CVSS Data Structures](/api/cvss/cvss3x) - Understanding parsed data
- [Error Handling Guide](/api/error-handling) - Comprehensive error handling
