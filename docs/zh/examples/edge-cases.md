# 边缘情况示例

本示例演示如何处理边缘情况、错误条件和使用 CVSS Skills 时的复杂场景。

## 概述

边缘情况包括：

- 无效向量格式
- 格式错误的指标值
- 版本兼容性问题
- 边界条件
- 性能边缘情况
- 内存约束

## 输入验证边缘情况

### 无效向量格式

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
        {"", "空字符串"},
        {"CVSS", "不完整前缀"},
        {"CVSS:2.0/AV:N", "不支持的版本"},
        {"CVSS:3.1", "缺少指标"},
        {"CVSS:3.1/AV:N", "不完整的基础指标"},
        {"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "无效指标值"},
        {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/INVALID:X", "未知指标"},
        {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L", "重复指标"},
    }

    fmt.Println("=== 无效向量格式处理 ===")
    
    for i, test := range invalidVectors {
        fmt.Printf("测试 %d: %s\n", i+1, test.description)
        fmt.Printf("向量: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if err != nil {
            fmt.Printf("✓ 预期错误: %v\n", err)
        } else {
            fmt.Printf("✗ 意外成功: %s\n", vector.String())
        }
        fmt.Println()
    }
}
```

### 边界值测试

```go
func testBoundaryValues() {
    boundaryTests := []struct {
        vector      string
        description string
        expectError bool
    }{
        {
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.0 (最低支持版本)",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.1 (最高支持版本)",
            false,
        },
        {
            "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.2 (不支持的未来版本)",
            true,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "所有影响为无 (分数 0.0)",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "作用域改变 (最高分数)",
            false,
        },
    }

    fmt.Println("=== 边界值测试 ===")
    
    for i, test := range boundaryTests {
        fmt.Printf("测试 %d: %s\n", i+1, test.description)
        fmt.Printf("向量: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if test.expectError {
            if err != nil {
                fmt.Printf("✓ 预期错误: %v\n", err)
            } else {
                fmt.Printf("✗ 预期错误但得到成功\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ 意外错误: %v\n", err)
            } else {
                calculator := cvss.NewCalculator(vector)
                score, _ := calculator.Calculate()
                fmt.Printf("✓ 成功: 分数 %.1f\n", score)
            }
        }
        fmt.Println()
    }
}
```

## 内存和性能边缘情况

### 大向量处理

```go
func testLargeVectorProcessing() {
    fmt.Println("=== 大向量处理测试 ===")
    
    // 生成大量向量
    vectorCount := 10000
    vectors := generateTestVectors(vectorCount)
    
    fmt.Printf("处理 %d 个向量...\n", vectorCount)
    
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
        
        // 进度指示器
        if (i+1)%1000 == 0 {
            fmt.Printf("  已处理 %d/%d 个向量\n", i+1, vectorCount)
        }
    }
    
    duration := time.Since(start)
    
    fmt.Printf("\n结果:\n")
    fmt.Printf("  总向量数: %d\n", vectorCount)
    fmt.Printf("  成功: %d\n", successCount)
    fmt.Printf("  错误: %d\n", errorCount)
    fmt.Printf("  持续时间: %v\n", duration)
    fmt.Printf("  速率: %.0f 向量/秒\n", float64(vectorCount)/duration.Seconds())
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

### 内存泄漏检测

```go
func testMemoryUsage() {
    fmt.Println("=== 内存使用测试 ===")
    
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    fmt.Printf("初始内存: %d KB\n", m1.Alloc/1024)
    
    // 处理许多向量
    for i := 0; i < 100000; i++ {
        vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector, err := parser.ParseString(vectorStr)
        
        if err == nil {
            calculator := cvss.NewCalculator(vector)
            calculator.Calculate()
        }
        
        // 定期强制 GC
        if i%10000 == 0 {
            runtime.GC()
        }
    }
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    fmt.Printf("最终内存: %d KB\n", m2.Alloc/1024)
    fmt.Printf("内存增加: %d KB\n", (m2.Alloc-m1.Alloc)/1024)
    
    if m2.Alloc-m1.Alloc < 1024*1024 { // 少于 1MB 增加
        fmt.Println("✓ 内存使用在可接受范围内")
    } else {
        fmt.Println("✗ 检测到潜在内存泄漏")
    }
}
```

## 并发处理边缘情况

### 竞态条件测试

```go
func testConcurrentParsing() {
    fmt.Println("=== 并发解析测试 ===")
    
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
    
    fmt.Printf("结果:\n")
    fmt.Printf("  协程数: %d\n", goroutineCount)
    fmt.Printf("  成功: %d\n", successCount)
    fmt.Printf("  错误: %d\n", errorCount)
    fmt.Printf("  持续时间: %v\n", duration)
    
    if errorCount == 0 {
        fmt.Println("✓ 未检测到竞态条件")
    } else {
        fmt.Println("✗ 检测到潜在竞态条件")
    }
}
```

### 资源耗尽测试

```go
func testResourceExhaustion() {
    fmt.Println("=== 资源耗尽测试 ===")
    
    // 测试极长的向量字符串
    longVectors := []string{
        strings.Repeat("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/", 1000),
        "CVSS:3.1/" + strings.Repeat("AV:N/", 10000),
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/" + strings.Repeat("X", 100000),
    }
    
    for i, vectorStr := range longVectors {
        fmt.Printf("测试 %d: 向量长度 %d 字符\n", i+1, len(vectorStr))
        
        start := time.Now()
        _, err := parser.ParseString(vectorStr)
        duration := time.Since(start)
        
        if err != nil {
            fmt.Printf("✓ 预期错误: %v (耗时 %v)\n", err, duration)
        } else {
            fmt.Printf("✗ 意外成功 (耗时 %v)\n", duration)
        }
        
        if duration > time.Second {
            fmt.Printf("⚠ 检测到慢解析: %v\n", duration)
        }
        fmt.Println()
    }
}
```

## 错误恢复和弹性

### 优雅错误处理

```go
func demonstrateGracefulErrorHandling() {
    problematicVectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 有效
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 无效 AV
        "",                                                // 空
        "INVALID",                                         // 完全无效
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",      // 缺少指标
    }
    
    fmt.Println("=== 优雅错误处理 ===")
    
    results := processVectorsWithRecovery(problematicVectors)
    
    fmt.Printf("处理结果:\n")
    fmt.Printf("  总向量数: %d\n", len(problematicVectors))
    fmt.Printf("  成功: %d\n", results.Successful)
    fmt.Printf("  失败: %d\n", results.Failed)
    fmt.Printf("  成功率: %.1f%%\n", float64(results.Successful)/float64(len(problematicVectors))*100)
    
    if len(results.Errors) > 0 {
        fmt.Printf("\n错误摘要:\n")
        errorCounts := make(map[string]int)
        for _, err := range results.Errors {
            errorType := categorizeError(err)
            errorCounts[errorType]++
        }
        
        for errorType, count := range errorCounts {
            fmt.Printf("  %s: %d 次\n", errorType, count)
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
                    results.Errors = append(results.Errors, fmt.Errorf("向量 %d 中的恐慌: %v", i, r))
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
        return "解析错误"
    } else if strings.Contains(errStr, "invalid") {
        return "验证错误"
    } else if strings.Contains(errStr, "panic") {
        return "运行时错误"
    } else {
        return "未知错误"
    }
}
```

### 回退机制

```go
func demonstrateFallbackMechanisms() {
    fmt.Println("=== 回退机制 ===")
    
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 有效
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 无效 - 尝试回退
        "COMPLETELY_INVALID",                              // 无效 - 使用默认
    }
    
    for i, vectorStr := range vectors {
        fmt.Printf("向量 %d: %s\n", i+1, vectorStr)
        
        result := parseWithFallback(vectorStr)
        
        fmt.Printf("  结果: %s\n", result.Status)
        fmt.Printf("  分数: %.1f\n", result.Score)
        fmt.Printf("  方法: %s\n", result.Method)
        
        if result.Error != nil {
            fmt.Printf("  错误: %v\n", result.Error)
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
    // 尝试主要解析
    vector, err := parser.ParseString(vectorStr)
    
    if err == nil {
        calculator := cvss.NewCalculator(vector)
        score, calcErr := calculator.Calculate()
        
        if calcErr == nil {
            return FallbackResult{
                Status: "成功",
                Score:  score,
                Method: "主要解析器",
            }
        }
    }
    
    // 尝试带修正的回退解析
    correctedVector := attemptVectorCorrection(vectorStr)
    if correctedVector != vectorStr {
        vector, err := parser.ParseString(correctedVector)
        
        if err == nil {
            calculator := cvss.NewCalculator(vector)
            score, calcErr := calculator.Calculate()
            
            if calcErr == nil {
                return FallbackResult{
                    Status: "成功 (已修正)",
                    Score:  score,
                    Method: "回退解析器",
                }
            }
        }
    }
    
    // 使用默认分数
    return FallbackResult{
        Status: "失败",
        Score:  5.0, // 默认中等严重性
        Method: "默认分数",
        Error:  err,
    }
}

func attemptVectorCorrection(vectorStr string) string {
    // 简单的修正尝试
    corrections := map[string]string{
        "AV:X": "AV:N", // 未知攻击向量 -> 网络
        "AC:X": "AC:L", // 未知复杂度 -> 低
        "PR:X": "PR:N", // 未知权限 -> 无
        "UI:X": "UI:N", // 未知交互 -> 无
        "S:X":  "S:U",  // 未知作用域 -> 不变
        "C:X":  "C:L",  // 未知影响 -> 低
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

## 复杂场景测试

### 版本兼容性边缘情况

```go
func testVersionCompatibility() {
    fmt.Println("=== 版本兼容性测试 ===")
    
    versionTests := []struct {
        vector      string
        description string
        expectError bool
    }{
        {
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.0 标准向量",
            false,
        },
        {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS 3.1 标准向量",
            false,
        },
        {
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS 2.0 向量 (不支持)",
            true,
        },
        {
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS 4.0 向量 (未来版本)",
            true,
        },
    }
    
    for i, test := range versionTests {
        fmt.Printf("测试 %d: %s\n", i+1, test.description)
        fmt.Printf("向量: %s\n", test.vector)
        
        vector, err := parser.ParseString(test.vector)
        
        if test.expectError {
            if err != nil {
                fmt.Printf("✓ 预期错误: %v\n", err)
            } else {
                fmt.Printf("✗ 预期错误但得到成功\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ 意外错误: %v\n", err)
            } else {
                fmt.Printf("✓ 成功: 版本 %d.%d\n", vector.MajorVersion, vector.MinorVersion)
            }
        }
        fmt.Println()
    }
}
```

### 压力测试

```go
func performStressTest() {
    fmt.Println("=== 压力测试 ===")
    
    // 快速连续解析测试
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    iterations := 100000
    
    fmt.Printf("执行 %d 次快速解析操作...\n", iterations)
    
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
    
    fmt.Printf("结果:\n")
    fmt.Printf("  迭代次数: %d\n", iterations)
    fmt.Printf("  错误: %d\n", errorCount)
    fmt.Printf("  成功率: %.2f%%\n", float64(iterations-errorCount)/float64(iterations)*100)
    fmt.Printf("  持续时间: %v\n", duration)
    fmt.Printf("  速率: %.0f 操作/秒\n", float64(iterations)/duration.Seconds())
    
    if errorCount == 0 {
        fmt.Println("✓ 压力测试通过")
    } else {
        fmt.Printf("✗ 压力测试失败，有 %d 个错误\n", errorCount)
    }
}
```

## 边缘情况处理最佳实践

### 防御性编程

```go
func safeVectorProcessing(vectorStr string) (float64, error) {
    // 输入验证
    if vectorStr == "" {
        return 0, fmt.Errorf("空向量字符串")
    }
    
    if len(vectorStr) > 1000 {
        return 0, fmt.Errorf("向量字符串过长: %d 字符", len(vectorStr))
    }
    
    // 超时保护
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
        return 0, fmt.Errorf("处理超时")
    }
}
```

### 错误分类和报告

```go
func classifyAndReportErrors(vectors []string) {
    fmt.Println("=== 错误分类和报告 ===")
    
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
    
    fmt.Printf("错误统计:\n")
    for category, count := range errorStats {
        fmt.Printf("  %s: %d\n", category, count)
    }
    
    if len(allErrors) > 0 {
        fmt.Printf("\n示例错误:\n")
        for i, err := range allErrors {
            if i >= 5 { // 只显示前 5 个错误
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
        return "超时"
    case strings.Contains(errStr, "empty"):
        return "输入验证"
    case strings.Contains(errStr, "too long"):
        return "输入验证"
    case strings.Contains(errStr, "parse"):
        return "解析错误"
    case strings.Contains(errStr, "invalid"):
        return "验证错误"
    default:
        return "未知"
    }
}
```

## 测试和验证

### 综合边缘情况测试套件

```go
func runEdgeCaseTestSuite() {
    fmt.Println("=== 综合边缘情况测试套件 ===")
    
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
        fmt.Printf("\n运行测试 %d...\n", i+1)
        
        func() {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Printf("✗ 测试 %d 因恐慌失败: %v\n", i+1, r)
                    failed++
                } else {
                    fmt.Printf("✓ 测试 %d 完成\n", i+1)
                    passed++
                }
            }()
            
            test()
        }()
    }
    
    fmt.Printf("\n测试套件结果:\n")
    fmt.Printf("  通过: %d\n", passed)
    fmt.Printf("  失败: %d\n", failed)
    fmt.Printf("  总计: %d\n", passed+failed)
    
    if failed == 0 {
        fmt.Println("✓ 所有边缘情况测试通过")
    } else {
        fmt.Printf("✗ %d 个边缘情况测试失败\n", failed)
    }
}
```

## 下一步

掌握边缘情况处理后，您可以探索：

- [性能优化](/zh/examples/performance) - 高级优化技术
- [生产部署](/zh/examples/edge-cases) - 企业部署模式
- [监控和告警](/zh/examples/monitoring) - 生产监控策略

## 相关文档

- [错误处理指南](/zh/api/cvss/) - 全面的错误处理
- [性能指南](/zh/examples/performance) - 性能优化
- [测试指南](/zh/api/cvss/) - 测试策略和最佳实践
