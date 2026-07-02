# Testing Guide

This comprehensive guide covers testing strategies, patterns, and best practices for applications using CVSS Skills.

## Overview

Effective testing ensures:

- Correct CVSS parsing and calculation
- Reliable error handling
- Performance under load
- Security vulnerability detection
- Compliance with requirements

## Testing Strategy

### Test Pyramid

```
    /\
   /  \    E2E Tests (Few)
  /____\
 /      \   Integration Tests (Some)
/________\  Unit Tests (Many)
```

### Test Categories

1. **Unit Tests** - Individual functions and methods
2. **Integration Tests** - Component interactions
3. **End-to-End Tests** - Complete workflows
4. **Performance Tests** - Load and stress testing
5. **Security Tests** - Vulnerability scanning
6. **Compliance Tests** - Regulatory requirements

## Unit Testing

### Basic Unit Tests

```go
package cvss_test

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func TestVectorParsing(t *testing.T) {
    testCases := []struct {
        name          string
        vector        string
        expectedScore float64
        expectError   bool
    }{
        {
            name:          "Valid high severity vector",
            vector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectedScore: 9.8,
            expectError:   false,
        },
        {
            name:          "Valid medium severity vector",
            vector:        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            expectedScore: 3.8,
            expectError:   false,
        },
        {
            name:        "Invalid vector format",
            vector:      "INVALID",
            expectError: true,
        },
        {
            name:        "Empty vector",
            vector:      "",
            expectError: true,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            vector, err := parser.ParseString(tc.vector)

            if tc.expectError {
                assert.Error(t, err)
                return
            }

            require.NoError(t, err)
            require.NotNil(t, vector)

            calculator := cvss.NewCalculator(vector)
            score, err := calculator.Calculate()

            require.NoError(t, err)
            assert.InDelta(t, tc.expectedScore, score, 0.1)
        })
    }
}
```

### Test Fixtures and Helpers

```go
// Test fixtures for common test data
type TestFixtures struct {
    ValidVectors   []string
    InvalidVectors []string
    EdgeCases      []string
}

func NewTestFixtures() *TestFixtures {
    return &TestFixtures{
        ValidVectors: []string{
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
        },
        InvalidVectors: []string{
            "",
            "INVALID",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        EdgeCases: []string{
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        },
    }
}

// Test helpers
func parseVector(t *testing.T, vectorStr string) *cvss.Cvss3x {
    t.Helper()

    vector, err := parser.ParseString(vectorStr)
    require.NoError(t, err)

    return vector
}

func calculateScore(t *testing.T, vector *cvss.Cvss3x) float64 {
    t.Helper()
    
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    require.NoError(t, err)
    
    return score
}

func assertScoreInRange(t *testing.T, score, min, max float64) {
    t.Helper()
    
    assert.GreaterOrEqual(t, score, min, "Score should be >= %f", min)
    assert.LessOrEqual(t, score, max, "Score should be <= %f", max)
}
```

### Property-Based Testing

```go
import "github.com/leanovate/gopter"
import "github.com/leanovate/gopter/gen"
import "github.com/leanovate/gopter/prop"

func TestCVSSProperties(t *testing.T) {
    properties := gopter.NewProperties(nil)

    // Property: All valid CVSS vectors should produce scores between 0.0 and 10.0
    properties.Property("CVSS scores are in valid range", prop.ForAll(
        func(av, ac, pr, ui, s, c, i, a string) bool {
            vector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
                av, ac, pr, ui, s, c, i, a)
            
            parser := parser.NewCvss3xParser(vector)
            parsedVector, err := parser.Parse()
            if err != nil {
                return true // Invalid vectors are expected to fail
            }            
            calculator := cvss.NewCalculator(parsedVector)
            score, err := calculator.Calculate()
            if err != nil {
                return false
            }
            
            return score >= 0.0 && score <= 10.0
        },
        gen.OneConstOf("N", "A", "L", "P"),     // AV
        gen.OneConstOf("L", "H"),               // AC
        gen.OneConstOf("N", "L", "H"),          // PR
        gen.OneConstOf("N", "R"),               // UI
        gen.OneConstOf("U", "C"),               // S
        gen.OneConstOf("N", "L", "H"),          // C
        gen.OneConstOf("N", "L", "H"),          // I
        gen.OneConstOf("N", "L", "H"),          // A
    ))

    // Property: Higher impact should generally result in higher scores
    properties.Property("Higher impact increases score", prop.ForAll(
        func() bool {
            baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:%s/I:%s/A:%s"
            
            lowVector := fmt.Sprintf(baseVector, "L", "L", "L")
            highVector := fmt.Sprintf(baseVector, "H", "H", "H")
            
            lowScore := calculateScore(t, parseVector(t, lowVector))
            highScore := calculateScore(t, parseVector(t, highVector))
            
            return highScore > lowScore
        },
    ))

    properties.TestingRun(t)
}
```

## Integration Testing

### Component Integration

```go
func TestCVSSServiceIntegration(t *testing.T) {
    // Setup test service
    service := setupTestService(t)
    defer teardownTestService(service)

    t.Run("Process single vector", func(t *testing.T) {
        vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        result, err := service.ProcessVector(context.Background(), vector)
        
        require.NoError(t, err)
        assert.Equal(t, vector, result.Vector)
        assert.InDelta(t, 9.8, result.Score, 0.1)
        assert.Equal(t, "Critical", result.Severity)
    })

    t.Run("Process batch vectors", func(t *testing.T) {
        vectors := []string{
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        }
        
        results, err := service.ProcessVectorsBatch(context.Background(), vectors)
        
        require.NoError(t, err)
        assert.Len(t, results, 2)
        assert.Greater(t, results[0].Score, results[1].Score)
    })
}

func setupTestService(t *testing.T) *CVSSService {
    config := &Config{
        CacheSize: 100,
        LogLevel:  "debug",
    }
    
    service := NewCVSSService(config)
    return service
}
```

### Database Integration

```go
func TestDatabaseIntegration(t *testing.T) {
    db := setupTestDB(t)
    defer teardownTestDB(db)

    repo := NewVectorRepository(db)

    t.Run("Store and retrieve vector", func(t *testing.T) {
        vector := &VectorRecord{
            ID:       "test-1",
            Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            Score:    9.8,
            Severity: "Critical",
        }

        err := repo.Store(context.Background(), vector)
        require.NoError(t, err)

        retrieved, err := repo.GetByID(context.Background(), "test-1")
        require.NoError(t, err)
        assert.Equal(t, vector.Vector, retrieved.Vector)
        assert.Equal(t, vector.Score, retrieved.Score)
    })

    t.Run("Query by severity", func(t *testing.T) {
        vectors, err := repo.GetBySeverity(context.Background(), "Critical")
        require.NoError(t, err)
        
        for _, v := range vectors {
            assert.Equal(t, "Critical", v.Severity)
            assert.GreaterOrEqual(t, v.Score, 9.0)
        }
    })
}
```

## End-to-End Testing

### HTTP API Testing

```go
func TestHTTPAPIEndToEnd(t *testing.T) {
    server := setupTestServer(t)
    defer server.Close()

    client := &http.Client{Timeout: 10 * time.Second}

    t.Run("Analyze vector endpoint", func(t *testing.T) {
        payload := map[string]interface{}{
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        
        body, _ := json.Marshal(payload)
        resp, err := client.Post(
            server.URL+"/api/v1/vectors/analyze",
            "application/json",
            bytes.NewBuffer(body),
        )
        
        require.NoError(t, err)
        defer resp.Body.Close()
        
        assert.Equal(t, http.StatusOK, resp.StatusCode)
        
        var result map[string]interface{}
        err = json.NewDecoder(resp.Body).Decode(&result)
        require.NoError(t, err)
        
        assert.Equal(t, 9.8, result["score"])
        assert.Equal(t, "Critical", result["severity"])
    })

    t.Run("Batch analysis endpoint", func(t *testing.T) {
        payload := map[string]interface{}{
            "vectors": []string{
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            },
        }
        
        body, _ := json.Marshal(payload)
        resp, err := client.Post(
            server.URL+"/api/v1/vectors/batch",
            "application/json",
            bytes.NewBuffer(body),
        )
        
        require.NoError(t, err)
        defer resp.Body.Close()
        
        assert.Equal(t, http.StatusOK, resp.StatusCode)
        
        var result map[string]interface{}
        err = json.NewDecoder(resp.Body).Decode(&result)
        require.NoError(t, err)
        
        results := result["results"].([]interface{})
        assert.Len(t, results, 2)
    })
}
```

## Testing Error Conditions

Test the real error shapes: parse sentinels via `errors.Is`, and validation via `errors.As` on `cvss.ValidationErrors` (see [Error Handling](/api/error-handling)).

```go
func TestParseSentinelErrors(t *testing.T) {
    // Missing CVSS: prefix
    _, err := parser.ParseString("not-a-vector")
    assert.ErrorIs(t, err, parser.ErrParserMagicHead)

    // Duplicate metric key (AV appears twice)
    _, err = parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:P")
    assert.ErrorIs(t, err, parser.ErrDuplicateMetric)

    // Unknown metric value -> plain fmt.Errorf (not a sentinel)
    _, err = parser.ParseString("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    require.Error(t, err)
    assert.False(t, errors.Is(err, parser.ErrParserMagicHead))
}

func TestValidationReportsAllMissingMetrics(t *testing.T) {
    // Parses fine, but is missing C/I/A base metrics
    cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
    require.NoError(t, err)

    err = cv.Validate()
    require.Error(t, err)

    var ve cvss.ValidationErrors
    require.True(t, errors.As(err, &ve))
    assert.ElementsMatch(t, []string{"C", "I", "A"}, ve.MissingMetrics())

    // Calculate() surfaces the same incompleteness via Check()'s error
    _, err = cvss.NewCalculator(cv).Calculate()
    require.Error(t, err)
}

func TestParseDoesNotPanicOnMalformedInput(t *testing.T) {
    inputs := []string{
        "",
        "CVSS:3.1",
        "CVSS:3.1/",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\x00",
        strings.Repeat("CVSS:3.1/AV:N/", 500),
    }
    for _, in := range inputs {
        assert.NotPanics(t, func() {
            _, _ = parser.ParseString(in)
        })
    }
}
```

## Performance Testing

### Benchmark Tests

```go
func BenchmarkVectorProcessing(b *testing.B) {
    vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        parsedVector, _ := parser.ParseString(vector)
        calculator := cvss.NewCalculator(parsedVector)
        calculator.Calculate()
    }
}

func BenchmarkBatchProcessing(b *testing.B) {
    vectors := generateTestVectors(1000)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ProcessVectorsBatch(vectors)
    }
}

func BenchmarkConcurrentProcessing(b *testing.B) {
    vectors := generateTestVectors(1000)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ProcessVectorsConcurrent(vectors, 8)
    }
}
```

### Load Testing

```go
func TestLoadHandling(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }

    server := setupTestServer(t)
    defer server.Close()

    // Test configuration
    concurrency := 50
    requests := 1000
    timeout := 30 * time.Second

    results := make(chan TestResult, requests)
    
    // Start load test
    start := time.Now()
    
    for i := 0; i < concurrency; i++ {
        go func() {
            client := &http.Client{Timeout: 5 * time.Second}
            
            for j := 0; j < requests/concurrency; j++ {
                result := sendTestRequest(client, server.URL)
                results <- result
            }
        }()
    }

    // Collect results
    var successful, failed int
    var totalDuration time.Duration
    
    for i := 0; i < requests; i++ {
        select {
        case result := <-results:
            if result.Success {
                successful++
                totalDuration += result.Duration
            } else {
                failed++
            }
        case <-time.After(timeout):
            t.Fatal("Load test timed out")
        }
    }

    duration := time.Since(start)
    
    // Assertions
    successRate := float64(successful) / float64(requests) * 100
    avgDuration := totalDuration / time.Duration(successful)
    requestsPerSecond := float64(requests) / duration.Seconds()

    t.Logf("Load test results:")
    t.Logf("  Total requests: %d", requests)
    t.Logf("  Successful: %d (%.1f%%)", successful, successRate)
    t.Logf("  Failed: %d", failed)
    t.Logf("  Duration: %v", duration)
    t.Logf("  Avg response time: %v", avgDuration)
    t.Logf("  Requests/sec: %.1f", requestsPerSecond)

    assert.GreaterOrEqual(t, successRate, 95.0, "Success rate should be >= 95%")
    assert.Less(t, avgDuration, 100*time.Millisecond, "Avg response time should be < 100ms")
    assert.GreaterOrEqual(t, requestsPerSecond, 100.0, "Should handle >= 100 requests/sec")
}

type TestResult struct {
    Success  bool
    Duration time.Duration
    Error    error
}
```

## Security Testing

### Input Validation Testing

```go
func TestSecurityInputValidation(t *testing.T) {
    maliciousInputs := []string{
        // SQL injection attempts
        "'; DROP TABLE vectors; --",
        "CVSS:3.1/AV:N'; DELETE FROM users; --",
        
        // XSS attempts
        "<script>alert('xss')</script>",
        "CVSS:3.1/AV:<script>alert(1)</script>",
        
        // Path traversal
        "../../../etc/passwd",
        "CVSS:3.1/AV:../../../etc/passwd",
        
        // Buffer overflow attempts
        strings.Repeat("A", 10000),
        "CVSS:3.1/" + strings.Repeat("AV:N/", 1000),
        
        // Null bytes
        "CVSS:3.1/AV:N\x00/AC:L",
        
        // Unicode attacks
        "CVSS:3.1/AV:N\u202e/AC:L",
    }

    for _, input := range maliciousInputs {
        t.Run(fmt.Sprintf("Malicious input: %s", truncateString(input, 50)), func(t *testing.T) {
            parser := parser.NewCvss3xParser(input)
            _, err := parser.Parse()
            
            // Should either return an error or handle gracefully
            // Should never cause panic or security issues
            assert.NotPanics(t, func() {
                parser.Parse()
            })
        })
    }
}

func TestRateLimiting(t *testing.T) {
    server := setupTestServer(t)
    defer server.Close()

    client := &http.Client{Timeout: 5 * time.Second}
    
    // Send requests rapidly to trigger rate limiting
    var responses []int
    for i := 0; i < 100; i++ {
        resp, err := client.Get(server.URL + "/api/v1/health")
        if err != nil {
            continue
        }
        responses = append(responses, resp.StatusCode)
        resp.Body.Close()
    }

    // Should see some 429 (Too Many Requests) responses
    rateLimited := 0
    for _, status := range responses {
        if status == 429 {
            rateLimited++
        }
    }

    assert.Greater(t, rateLimited, 0, "Rate limiting should be active")
}
```

## Test Data Management

### Test Data Generation

```go
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

func loadTestDataFromFile(t *testing.T, filename string) []TestCase {
    data, err := os.ReadFile(filename)
    require.NoError(t, err)

    var testCases []TestCase
    err = json.Unmarshal(data, &testCases)
    require.NoError(t, err)

    return testCases
}

type TestCase struct {
    Name          string  `json:"name"`
    Vector        string  `json:"vector"`
    ExpectedScore float64 `json:"expected_score"`
    ExpectedError bool    `json:"expected_error"`
}
```

## Test Automation

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Go
      uses: actions/setup-go@v2
      with:
        go-version: 1.21
    
    - name: Cache dependencies
      uses: actions/cache@v2
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
    
    - name: Install dependencies
      run: go mod download
    
    - name: Run unit tests
      run: go test -v -race -coverprofile=coverage.out ./...
    
    - name: Run integration tests
      run: go test -v -tags=integration ./...
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/testdb?sslmode=disable
    
    - name: Run security tests
      run: go test -v -tags=security ./...
    
    - name: Upload coverage
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage.out
```

### Test Reporting

```go
func generateTestReport(results []TestResult) *TestReport {
    report := &TestReport{
        Timestamp: time.Now(),
        Summary: TestSummary{
            Total:   len(results),
            Passed:  0,
            Failed:  0,
            Skipped: 0,
        },
        Details: results,
    }
    
    for _, result := range results {
        switch result.Status {
        case "PASS":
            report.Summary.Passed++
        case "FAIL":
            report.Summary.Failed++
        case "SKIP":
            report.Summary.Skipped++
        }
    }
    
    report.Summary.PassRate = float64(report.Summary.Passed) / float64(report.Summary.Total) * 100
    
    return report
}

type TestReport struct {
    Timestamp time.Time    `json:"timestamp"`
    Summary   TestSummary  `json:"summary"`
    Details   []TestResult `json:"details"`
}

type TestSummary struct {
    Total    int     `json:"total"`
    Passed   int     `json:"passed"`
    Failed   int     `json:"failed"`
    Skipped  int     `json:"skipped"`
    PassRate float64 `json:"pass_rate"`
}
```

## Best Practices

### Testing Guidelines

1. **Test Naming**: Use descriptive test names that explain the scenario
2. **Test Structure**: Follow Arrange-Act-Assert pattern
3. **Test Independence**: Each test should be independent and repeatable
4. **Test Data**: Use fixtures and factories for consistent test data
5. **Error Testing**: Test both success and failure scenarios
6. **Performance**: Include performance benchmarks for critical paths

### Code Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Check coverage threshold
go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if($1<80) exit 1}'
```

## Next Steps

After implementing comprehensive testing:

- [Performance Optimization](/examples/performance) - Optimize based on test results
- [Monitoring](/examples/monitoring) - Production monitoring and alerting
- [Security Hardening](/examples/security) - Advanced security measures

## Related Documentation

- [Error Handling](/api/error-handling) - Error handling patterns
- [Performance Guide](/api/performance) - Performance optimization
- [Security Guide](/examples/security) - Security best practices
