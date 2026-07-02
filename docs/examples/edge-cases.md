# Edge Cases Examples

This example demonstrates how to handle edge cases, error conditions, and complex scenarios when working with CVSS Skills.

## Overview

Edge cases include:

- Invalid vector formats
- Malformed metric values
- Version compatibility issues
- Boundary conditions
- Performance edge cases
- Memory constraints

## Input Validation Edge Cases

### Invalid Vector Formats

```go
package main

import (
    "fmt"
    "strings"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    invalidVectors := []struct {
        vector      string
        description string
    }{
        {"", "Empty string"},
        {"CVSS", "Incomplete prefix"},
        {"CVSS:2.0/AV:N", "Unsupported version"},
        {"CVSS:3.1", "Missing metrics"},
        {"CVSS:3.1/AV:N", "Incomplete base metrics"},
        {"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Invalid metric value"},
        {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/INVALID:X", "Unknown metric"},
        {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L", "Duplicate metric"},
    }

    fmt.Println("=== Invalid Vector Format Handling ===")
    
    for i, test := range invalidVectors {
        fmt.Printf("Test %d: %s\n", i+1, test.description)
        fmt.Printf("Vector: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if err != nil {
            fmt.Printf("✓ Expected error: %v\n", err)
        } else {
            fmt.Printf("✗ Unexpected success: %s\n", vector.String())
        }
        fmt.Println()
    }
}
```

### Boundary Value Testing

```go
func testBoundaryValues() {
    boundaryTests := []struct {
        vector      string
        description string
        expectError bool
    }{
        {
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.0 (minimum supported version)",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.1 (maximum supported version)",
            false,
        },
        {
            "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.2 (unsupported future version)",
            true,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "All impacts None (score 0.0)",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Scope Changed (maximum score)",
            false,
        },
    }

    fmt.Println("=== Boundary Value Testing ===")
    
    for i, test := range boundaryTests {
        fmt.Printf("Test %d: %s\n", i+1, test.description)
        fmt.Printf("Vector: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if test.expectError {
            if err != nil {
                fmt.Printf("✓ Expected error: %v\n", err)
            } else {
                fmt.Printf("✗ Expected error but got success\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ Unexpected error: %v\n", err)
            } else {
                calculator := cvss.NewCalculator(vector)
                score, _ := calculator.Calculate()
                fmt.Printf("✓ Success: Score %.1f\n", score)
            }
        }
        fmt.Println()
    }
}
```

## Memory and Performance Edge Cases

### Large Vector Processing

```go
func testLargeVectorProcessing() {
    fmt.Println("=== Large Vector Processing Test ===")
    
    // Generate a large number of vectors
    vectorCount := 10000
    vectors := generateTestVectors(vectorCount)
    
    fmt.Printf("Processing %d vectors...\n", vectorCount)
    
    start := time.Now()
    successCount := 0
    errorCount := 0
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        
        if err != nil {
            errorCount++
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        _, err = calculator.Calculate()
        
        if err != nil {
            errorCount++
        } else {
            successCount++
        }
        
        // Progress indicator
        if (i+1)%1000 == 0 {
            fmt.Printf("  Processed %d/%d vectors\n", i+1, vectorCount)
        }
    }
    
    duration := time.Since(start)
    
    fmt.Printf("\nResults:\n")
    fmt.Printf("  Total vectors: %d\n", vectorCount)
    fmt.Printf("  Successful: %d\n", successCount)
    fmt.Printf("  Errors: %d\n", errorCount)
    fmt.Printf("  Duration: %v\n", duration)
    fmt.Printf("  Rate: %.0f vectors/second\n", float64(vectorCount)/duration.Seconds())
}

func generateTestVectors(count int) []string {
    vectors := make([]string, count)
    
    attackVectors := []string{"N", "A", "L", "P"}
    complexities := []string{"L", "H"}
    privileges := []string{"N", "L", "H"}
    interactions := []string{"N", "R"}
    scopes := []string{"U", "C"}
    impacts := []string{"N", "L", "H"}
    
    for i := 0; i < count; i++ {
        vector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
            attackVectors[i%len(attackVectors)],
            complexities[i%len(complexities)],
            privileges[i%len(privileges)],
            interactions[i%len(interactions)],
            scopes[i%len(scopes)],
            impacts[i%len(impacts)],
            impacts[(i+1)%len(impacts)],
            impacts[(i+2)%len(impacts)])
        
        vectors[i] = vector
    }
    
    return vectors
}
```

### Memory Leak Detection

```go
func testMemoryUsage() {
    fmt.Println("=== Memory Usage Test ===")
    
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    fmt.Printf("Initial memory: %d KB\n", m1.Alloc/1024)
    
    // Process many vectors
    for i := 0; i < 100000; i++ {
        vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector, err := parser.ParseString(vectorStr)
        
        if err == nil {
            calculator := cvss.NewCalculator(vector)
            calculator.Calculate()
        }
        
        // Force GC periodically
        if i%10000 == 0 {
            runtime.GC()
        }
    }
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    fmt.Printf("Final memory: %d KB\n", m2.Alloc/1024)
    fmt.Printf("Memory increase: %d KB\n", (m2.Alloc-m1.Alloc)/1024)
    
    if m2.Alloc-m1.Alloc < 1024*1024 { // Less than 1MB increase
        fmt.Println("✓ Memory usage within acceptable limits")
    } else {
        fmt.Println("✗ Potential memory leak detected")
    }
}
```

## Concurrent Processing Edge Cases

### Race Condition Testing

```go
func testConcurrentParsing() {
    fmt.Println("=== Concurrent Parsing Test ===")
    
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    goroutineCount := 1000
    
    var wg sync.WaitGroup
    var mutex sync.Mutex
    successCount := 0
    errorCount := 0
    
    start := time.Now()
    
    for i := 0; i < goroutineCount; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            vector, err := parser.ParseString(vectorStr)
            
            mutex.Lock()
            if err != nil {
                errorCount++
            } else {
                calculator := cvss.NewCalculator(vector)
                _, err = calculator.Calculate()
                if err != nil {
                    errorCount++
                } else {
                    successCount++
                }
            }
            mutex.Unlock()
        }(i)
    }
    
    wg.Wait()
    duration := time.Since(start)
    
    fmt.Printf("Results:\n")
    fmt.Printf("  Goroutines: %d\n", goroutineCount)
    fmt.Printf("  Successful: %d\n", successCount)
    fmt.Printf("  Errors: %d\n", errorCount)
    fmt.Printf("  Duration: %v\n", duration)
    
    if errorCount == 0 {
        fmt.Println("✓ No race conditions detected")
    } else {
        fmt.Println("✗ Potential race conditions detected")
    }
}
```

### Resource Exhaustion Testing

```go
func testResourceExhaustion() {
    fmt.Println("=== Resource Exhaustion Test ===")
    
    // Test with extremely long vector strings
    longVectors := []string{
        strings.Repeat("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/", 1000),
        "CVSS:3.1/" + strings.Repeat("AV:N/", 10000),
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/" + strings.Repeat("X", 100000),
    }
    
    for i, vectorStr := range longVectors {
        fmt.Printf("Test %d: Vector length %d characters\n", i+1, len(vectorStr))
        
        start := time.Now()
        _, err := parser.ParseString(vectorStr)
        duration := time.Since(start)
        
        if err != nil {
            fmt.Printf("✓ Expected error: %v (took %v)\n", err, duration)
        } else {
            fmt.Printf("✗ Unexpected success (took %v)\n", duration)
        }
        
        if duration > time.Second {
            fmt.Printf("⚠ Slow parsing detected: %v\n", duration)
        }
        fmt.Println()
    }
}
```

## Error Recovery and Resilience

### Graceful Error Handling

```go
func demonstrateGracefulErrorHandling() {
    problematicVectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // Valid
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // Invalid AV
        "",                                                // Empty
        "INVALID",                                         // Completely invalid
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",      // Missing metric
    }
    
    fmt.Println("=== Graceful Error Handling ===")
    
    results := processVectorsWithRecovery(problematicVectors)
    
    fmt.Printf("Processing Results:\n")
    fmt.Printf("  Total vectors: %d\n", len(problematicVectors))
    fmt.Printf("  Successful: %d\n", results.Successful)
    fmt.Printf("  Failed: %d\n", results.Failed)
    fmt.Printf("  Success rate: %.1f%%\n", float64(results.Successful)/float64(len(problematicVectors))*100)
    
    if len(results.Errors) > 0 {
        fmt.Printf("\nError Summary:\n")
        errorCounts := make(map[string]int)
        for _, err := range results.Errors {
            errorType := categorizeError(err)
            errorCounts[errorType]++
        }
        
        for errorType, count := range errorCounts {
            fmt.Printf("  %s: %d occurrences\n", errorType, count)
        }
    }
}

type ProcessingResults struct {
    Successful int
    Failed     int
    Errors     []error
}

func processVectorsWithRecovery(vectors []string) ProcessingResults {
    results := ProcessingResults{}
    
    for i, vectorStr := range vectors {
        func() {
            defer func() {
                if r := recover(); r != nil {
                    results.Failed++
                    results.Errors = append(results.Errors, fmt.Errorf("panic in vector %d: %v", i, r))
                }
            }()
            
            vector, err := parser.ParseString(vectorStr)
            
            if err != nil {
                results.Failed++
                results.Errors = append(results.Errors, err)
                return
            }
            
            calculator := cvss.NewCalculator(vector)
            _, err = calculator.Calculate()
            
            if err != nil {
                results.Failed++
                results.Errors = append(results.Errors, err)
                return
            }
            
            results.Successful++
        }()
    }
    
    return results
}

func categorizeError(err error) string {
    errStr := err.Error()
    
    if strings.Contains(errStr, "parse") {
        return "Parse Error"
    } else if strings.Contains(errStr, "invalid") {
        return "Validation Error"
    } else if strings.Contains(errStr, "panic") {
        return "Runtime Error"
    } else {
        return "Unknown Error"
    }
}
```

### Fallback Mechanisms

```go
func demonstrateFallbackMechanisms() {
    fmt.Println("=== Fallback Mechanisms ===")
    
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // Valid
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // Invalid - try fallback
        "COMPLETELY_INVALID",                              // Invalid - use default
    }
    
    for i, vectorStr := range vectors {
        fmt.Printf("Vector %d: %s\n", i+1, vectorStr)
        
        result := parseWithFallback(vectorStr)
        
        fmt.Printf("  Result: %s\n", result.Status)
        fmt.Printf("  Score: %.1f\n", result.Score)
        fmt.Printf("  Method: %s\n", result.Method)
        
        if result.Error != nil {
            fmt.Printf("  Error: %v\n", result.Error)
        }
        fmt.Println()
    }
}

type FallbackResult struct {
    Status string
    Score  float64
    Method string
    Error  error
}

func parseWithFallback(vectorStr string) FallbackResult {
    // Try primary parsing
    vector, err := parser.ParseString(vectorStr)
    
    if err == nil {
        calculator := cvss.NewCalculator(vector)
        score, calcErr := calculator.Calculate()
        
        if calcErr == nil {
            return FallbackResult{
                Status: "Success",
                Score:  score,
                Method: "Primary Parser",
            }
        }
    }
    
    // Try fallback parsing with corrections
    correctedVector := attemptVectorCorrection(vectorStr)
    if correctedVector != vectorStr {
        vector, err := parser.ParseString(correctedVector)
        
        if err == nil {
            calculator := cvss.NewCalculator(vector)
            score, calcErr := calculator.Calculate()
            
            if calcErr == nil {
                return FallbackResult{
                    Status: "Success (Corrected)",
                    Score:  score,
                    Method: "Fallback Parser",
                }
            }
        }
    }
    
    // Use default score
    return FallbackResult{
        Status: "Failed",
        Score:  5.0, // Default medium severity
        Method: "Default Score",
        Error:  err,
    }
}

func attemptVectorCorrection(vectorStr string) string {
    // Simple correction attempts
    corrections := map[string]string{
        "AV:X": "AV:N", // Unknown attack vector -> Network
        "AC:X": "AC:L", // Unknown complexity -> Low
        "PR:X": "PR:N", // Unknown privileges -> None
        "UI:X": "UI:N", // Unknown interaction -> None
        "S:X":  "S:U",  // Unknown scope -> Unchanged
        "C:X":  "C:L",  // Unknown impact -> Low
        "I:X":  "I:L",
        "A:X":  "A:L",
    }
    
    corrected := vectorStr
    for invalid, valid := range corrections {
        corrected = strings.ReplaceAll(corrected, invalid, valid)
    }
    
    return corrected
}
```

## Complex Scenario Testing

### Version Compatibility Edge Cases

```go
func testVersionCompatibility() {
    fmt.Println("=== Version Compatibility Testing ===")
    
    versionTests := []struct {
        vector      string
        description string
        expectError bool
    }{
        {
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.0 standard vector",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.1 standard vector",
            false,
        },
        {
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS 2.0 vector (unsupported)",
            true,
        },
        {
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS 4.0 vector (future version)",
            true,
        },
    }
    
    for i, test := range versionTests {
        fmt.Printf("Test %d: %s\n", i+1, test.description)
        fmt.Printf("Vector: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if test.expectError {
            if err != nil {
                fmt.Printf("✓ Expected error: %v\n", err)
            } else {
                fmt.Printf("✗ Expected error but got success\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ Unexpected error: %v\n", err)
            } else {
                fmt.Printf("✓ Success: Version %d.%d\n", vector.MajorVersion, vector.MinorVersion)
            }
        }
        fmt.Println()
    }
}
```

### Stress Testing

```go
func performStressTest() {
    fmt.Println("=== Stress Testing ===")
    
    // Test with rapid-fire parsing
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    iterations := 100000
    
    fmt.Printf("Performing %d rapid parsing operations...\n", iterations)
    
    start := time.Now()
    errorCount := 0
    
    for i := 0; i < iterations; i++ {
        vector, err := parser.ParseString(vectorStr)
        
        if err != nil {
            errorCount++
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        _, err = calculator.Calculate()
        
        if err != nil {
            errorCount++
        }
    }
    
    duration := time.Since(start)
    
    fmt.Printf("Results:\n")
    fmt.Printf("  Iterations: %d\n", iterations)
    fmt.Printf("  Errors: %d\n", errorCount)
    fmt.Printf("  Success rate: %.2f%%\n", float64(iterations-errorCount)/float64(iterations)*100)
    fmt.Printf("  Duration: %v\n", duration)
    fmt.Printf("  Rate: %.0f ops/second\n", float64(iterations)/duration.Seconds())
    
    if errorCount == 0 {
        fmt.Println("✓ Stress test passed")
    } else {
        fmt.Printf("✗ Stress test failed with %d errors\n", errorCount)
    }
}
```

## Best Practices for Edge Case Handling

### Defensive Programming

```go
func safeVectorProcessing(vectorStr string) (float64, error) {
    // Input validation
    if vectorStr == "" {
        return 0, fmt.Errorf("empty vector string")
    }
    
    if len(vectorStr) > 1000 {
        return 0, fmt.Errorf("vector string too long: %d characters", len(vectorStr))
    }
    
    // Timeout protection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    resultChan := make(chan struct {
        score float64
        err   error
    }, 1)
    
    go func() {
        vector, err := parser.ParseString(vectorStr)
        
        if err != nil {
            resultChan <- struct {
                score float64
                err   error
            }{0, err}
            return
        }
        
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        
        resultChan <- struct {
            score float64
            err   error
        }{score, err}
    }()
    
    select {
    case result := <-resultChan:
        return result.score, result.err
    case <-ctx.Done():
        return 0, fmt.Errorf("processing timeout")
    }
}
```

### Error Classification and Reporting

```go
func classifyAndReportErrors(vectors []string) {
    fmt.Println("=== Error Classification and Reporting ===")
    
    errorStats := make(map[string]int)
    var allErrors []error
    
    for _, vectorStr := range vectors {
        _, err := safeVectorProcessing(vectorStr)
        if err != nil {
            allErrors = append(allErrors, err)
            category := classifyError(err)
            errorStats[category]++
        }
    }
    
    fmt.Printf("Error Statistics:\n")
    for category, count := range errorStats {
        fmt.Printf("  %s: %d\n", category, count)
    }
    
    if len(allErrors) > 0 {
        fmt.Printf("\nSample Errors:\n")
        for i, err := range allErrors {
            if i >= 5 { // Show only first 5 errors
                break
            }
            fmt.Printf("  %d. %v\n", i+1, err)
        }
    }
}

func classifyError(err error) string {
    errStr := strings.ToLower(err.Error())
    
    switch {
    case strings.Contains(errStr, "timeout"):
        return "Timeout"
    case strings.Contains(errStr, "empty"):
        return "Input Validation"
    case strings.Contains(errStr, "too long"):
        return "Input Validation"
    case strings.Contains(errStr, "parse"):
        return "Parse Error"
    case strings.Contains(errStr, "invalid"):
        return "Validation Error"
    default:
        return "Unknown"
    }
}
```

## Testing and Validation

### Comprehensive Edge Case Test Suite

```go
func runEdgeCaseTestSuite() {
    fmt.Println("=== Comprehensive Edge Case Test Suite ===")
    
    tests := []func(){
        testBoundaryValues,
        testConcurrentParsing,
        testMemoryUsage,
        testResourceExhaustion,
        testVersionCompatibility,
        performStressTest,
    }
    
    passed := 0
    failed := 0
    
    for i, test := range tests {
        fmt.Printf("\nRunning test %d...\n", i+1)
        
        func() {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Printf("✗ Test %d failed with panic: %v\n", i+1, r)
                    failed++
                } else {
                    fmt.Printf("✓ Test %d completed\n", i+1)
                    passed++
                }
            }()
            
            test()
        }()
    }
    
    fmt.Printf("\nTest Suite Results:\n")
    fmt.Printf("  Passed: %d\n", passed)
    fmt.Printf("  Failed: %d\n", failed)
    fmt.Printf("  Total: %d\n", passed+failed)
    
    if failed == 0 {
        fmt.Println("✓ All edge case tests passed")
    } else {
        fmt.Printf("✗ %d edge case tests failed\n", failed)
    }
}
```

## Next Steps

After mastering edge case handling, you can explore:

- [Performance Optimization](/examples/performance) - Advanced optimization techniques
- [Production Deployment](/examples/production) - Enterprise deployment patterns
- [Monitoring and Alerting](/examples/monitoring) - Production monitoring strategies

## Related Documentation

- [Error Handling Guide](/api/error-handling) - Comprehensive error handling
- [Performance Guide](/api/performance) - Performance optimization
- [Testing Guide](/api/testing) - Testing strategies and best practices
