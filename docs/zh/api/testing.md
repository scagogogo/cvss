# 测试指南

本指南全面介绍使用 CVSS Skills 的应用之测试策略、模式与最佳实践。

## 概述

有效的测试确保：

- CVSS 解析与计算正确
- 错误处理可靠
- 负载下的性能
- 安全漏洞检测
- 需求合规

## 测试策略

### 测试金字塔

```
    /\
   /  \    端到端测试（少量）
  /____\
 /      \   集成测试（适量）
/________\  单元测试（大量）
```

### 测试分类

1. **单元测试** - 单个函数与方法
2. **集成测试** - 组件间交互
3. **端到端测试** - 完整工作流
4. **性能测试** - 负载与压力测试
5. **安全测试** - 漏洞扫描
6. **合规测试** - 法规要求

## 单元测试

### 基础单元测试

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

### 测试夹具与辅助函数

```go
// 常用测试数据的测试夹具
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

// 测试辅助函数
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

### 基于属性的测试

```go
import "github.com/leanovate/gopter"
import "github.com/leanovate/gopter/gen"
import "github.com/leanovate/gopter/prop"

func TestCVSSProperties(t *testing.T) {
    properties := gopter.NewProperties(nil)

    // 属性：所有合法 CVSS 向量的评分应在 0.0 到 10.0 之间
    properties.Property("CVSS scores are in valid range", prop.ForAll(
        func(av, ac, pr, ui, s, c, i, a string) bool {
            vector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
                av, ac, pr, ui, s, c, i, a)
            
            parsedVector, err := parser.ParseString(vector)
            if err != nil {
                return true // 非法向量预期会失败
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

    // 属性：更高的影响通常导致更高的评分
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

## 集成测试

### 组件集成

```go
func TestCVSSServiceIntegration(t *testing.T) {
    // 搭建测试服务
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

### 数据库集成

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

## 端到端测试

### HTTP API 测试

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

## 错误条件测试

测试真实的错误形态：解析哨兵错误用 `errors.Is`，校验用 `cvss.ValidationErrors` 上的 `errors.As`（见[错误处理](/zh/api/error-handling)）。

```go
func TestParseSentinelErrors(t *testing.T) {
    // 缺少 CVSS: 前缀
    _, err := parser.ParseString("not-a-vector")
    assert.ErrorIs(t, err, parser.ErrParserMagicHead)

    // 重复指标键（AV 出现两次）
    _, err = parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:P")
    assert.ErrorIs(t, err, parser.ErrDuplicateMetric)

    // 未知指标值 -> 普通 fmt.Errorf（非哨兵）
    _, err = parser.ParseString("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    require.Error(t, err)
    assert.False(t, errors.Is(err, parser.ErrParserMagicHead))
}

func TestValidationReportsAllMissingMetrics(t *testing.T) {
    // 解析正常，但缺少 C/I/A 基础指标
    cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
    require.NoError(t, err)

    err = cv.Validate()
    require.Error(t, err)

    var ve cvss.ValidationErrors
    require.True(t, errors.As(err, &ve))
    assert.ElementsMatch(t, []string{"C", "I", "A"}, ve.MissingMetrics())

    // Calculate() 通过 Check() 的错误暴露同样的不完整性
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

## 性能测试

### 基准测试

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

### 负载测试

```go
func TestLoadHandling(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }

    server := setupTestServer(t)
    defer server.Close()

    // 测试配置
    concurrency := 50
    requests := 1000
    timeout := 30 * time.Second

    results := make(chan TestResult, requests)
    
    // 开始负载测试
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

    // 收集结果
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
    
    // 断言
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
    Status   string
    Success  bool
    Duration time.Duration
    Error    error
}
```

## 安全测试

### 输入校验测试

```go
func TestSecurityInputValidation(t *testing.T) {
    maliciousInputs := []string{
        // SQL 注入尝试
        "'; DROP TABLE vectors; --",
        "CVSS:3.1/AV:N'; DELETE FROM users; --",
        
        // XSS 尝试
        "<script>alert('xss')</script>",
        "CVSS:3.1/AV:<script>alert(1)</script>",
        
        // 路径遍历
        "../../../etc/passwd",
        "CVSS:3.1/AV:../../../etc/passwd",
        
        // 缓冲区溢出尝试
        strings.Repeat("A", 10000),
        "CVSS:3.1/" + strings.Repeat("AV:N/", 1000),
        
        // 空字节
        "CVSS:3.1/AV:N\x00/AC:L",
        
        // Unicode 攻击
        "CVSS:3.1/AV:N‮/AC:L",
    }

    for _, input := range maliciousInputs {
        t.Run(fmt.Sprintf("Malicious input: %s", truncateString(input, 50)), func(t *testing.T) {
            // 应返回错误或优雅处理
            // 绝不应导致 panic 或安全问题
            assert.NotPanics(t, func() {
                _, _ = parser.ParseString(input)
            })
        })
    }
}

func TestRateLimiting(t *testing.T) {
    server := setupTestServer(t)
    defer server.Close()

    client := &http.Client{Timeout: 5 * time.Second}
    
    // 快速发送请求以触发速率限制
    var responses []int
    for i := 0; i < 100; i++ {
        resp, err := client.Get(server.URL + "/api/v1/health")
        if err != nil {
            continue
        }
        responses = append(responses, resp.StatusCode)
        resp.Body.Close()
    }

    // 应看到一些 429（Too Many Requests）响应
    rateLimited := 0
    for _, status := range responses {
        if status == 429 {
            rateLimited++
        }
    }

    assert.Greater(t, rateLimited, 0, "Rate limiting should be active")
}
```

## 测试数据管理

### 测试数据生成

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

## 测试自动化

### CI/CD 集成

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

### 测试报告

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

## 最佳实践

### 测试准则

1. **测试命名**：使用描述性测试名，清楚说明场景
2. **测试结构**：遵循 Arrange-Act-Assert 模式
3. **测试独立性**：每个测试应独立且可重复
4. **测试数据**：用夹具与工厂保证数据一致
5. **错误测试**：同时测试成功与失败场景
6. **性能**：为关键路径加入性能基准

### 代码覆盖率

```bash
# 生成覆盖率报告
go test -coverprofile=coverage.out ./...

# 在浏览器中查看覆盖率
go tool cover -html=coverage.out

# 检查覆盖率阈值
go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if($1<80) exit 1}'
```

## 下一步

实现全面测试后：

- [性能优化](/zh/examples/performance) - 基于测试结果优化
- [监控](/zh/examples/monitoring) - 生产环境监控与告警
- [安全加固](/zh/examples/security) - 高级安全措施

## 相关文档

- [错误处理](/zh/api/error-handling) - 错误处理模式
- [性能指南](/zh/api/performance) - 性能优化
- [安全指南](/zh/examples/security) - 安全最佳实践
