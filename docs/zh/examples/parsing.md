# 向量解析示例

本示例演示了各种解析 CVSS 向量字符串的方法，包括不同格式、错误处理和验证技术。

## 概述

CVSS Skills 支持解析各种格式和配置的 CVSS 3.0 和 3.1 向量字符串。本指南涵盖：

- 基本向量解析
- 不同向量格式
- 错误处理和验证
- 批量解析
- 性能优化

## 基本向量解析

### 简单解析

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 基本 CVSS 3.1 向量
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // 创建解析器
    p := parser.NewCvss3xParser(vectorStr)
    
    // 解析向量
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }
    
    fmt.Printf("解析成功: %s\n", vector.String())
    fmt.Printf("版本: %d.%d\n", vector.MajorVersion, vector.MinorVersion)
}
```

### 解析不同 CVSS 版本

```go
func parseMultipleVersions() {
    vectors := map[string]string{
        "CVSS 3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS 3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    
    for version, vectorStr := range vectors {
        fmt.Printf("\n--- 解析 %s ---\n", version)
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            fmt.Printf("错误: %v\n", err)
            continue
        }
        
        fmt.Printf("向量: %s\n", vectorStr)
        fmt.Printf("解析版本: %d.%d\n", vector.MajorVersion, vector.MinorVersion)
        fmt.Printf("有效: %t\n", vector.IsValid())
    }
}
```

## 向量格式变化

### 仅基础指标

```go
func parseBaseOnly() {
    // 最小必需的基础指标
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    parser := parser.NewCvss3xParser(baseVector)
    vector, err := parser.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("基础向量: %s\n", vector.String())
    fmt.Printf("包含时间指标: %t\n", vector.HasTemporal())
    fmt.Printf("包含环境指标: %t\n", vector.HasEnvironmental())
}
```

### 带时间指标的向量

```go
func parseWithTemporal() {
    // 带时间指标的向量
    temporalVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
    
    parser := parser.NewCvss3xParser(temporalVector)
    vector, err := parser.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("时间向量: %s\n", vector.String())
    fmt.Printf("包含时间指标: %t\n", vector.HasTemporal())
    
    if vector.HasTemporal() {
        fmt.Printf("漏洞利用代码成熟度: %s\n", 
            vector.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue())
        fmt.Printf("修复级别: %s\n", 
            vector.Cvss3xTemporal.RemediationLevel.GetLongValue())
        fmt.Printf("报告可信度: %s\n", 
            vector.Cvss3xTemporal.ReportConfidence.GetLongValue())
    }
}
```

### 带环境指标的向量

```go
func parseWithEnvironmental() {
    // 带环境指标的向量
    envVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"
    
    parser := parser.NewCvss3xParser(envVector)
    vector, err := parser.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("环境向量: %s\n", vector.String())
    fmt.Printf("包含环境指标: %t\n", vector.HasEnvironmental())
    
    if vector.HasEnvironmental() {
        fmt.Printf("机密性需求: %s\n", 
            vector.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue())
        fmt.Printf("修改的攻击向量: %s\n", 
            vector.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue())
    }
}
```

### 包含所有指标的完整向量

```go
func parseCompleteVector() {
    // 包含基础、时间和环境指标的完整向量
    completeVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"
    
    parser := parser.NewCvss3xParser(completeVector)
    vector, err := parser.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("完整向量: %s\n", vector.String())
    fmt.Printf("包含时间指标: %t\n", vector.HasTemporal())
    fmt.Printf("包含环境指标: %t\n", vector.HasEnvironmental())
    fmt.Printf("总指标数: %d\n", countMetrics(vector))
}

func countMetrics(vector *cvss.Cvss3x) int {
    count := 8 // 基础指标
    if vector.HasTemporal() {
        count += 3 // 时间指标
    }
    if vector.HasEnvironmental() {
        count += 11 // 环境指标
    }
    return count
}
```

## 错误处理和验证

### 健壮的解析与错误处理

```go
func robustParsing(vectorStr string) (*cvss.Cvss3x, error) {
    // 输入验证
    if vectorStr == "" {
        return nil, fmt.Errorf("向量字符串不能为空")
    }
    
    if len(vectorStr) > 200 {
        return nil, fmt.Errorf("向量字符串过长: %d 字符", len(vectorStr))
    }
    
    if !strings.HasPrefix(vectorStr, "CVSS:") {
        return nil, fmt.Errorf("无效的向量格式: 必须以 'CVSS:' 开头")
    }
    
    // 带错误处理的解析
    parser := parser.NewCvss3xParser(vectorStr)
    vector, err := parser.Parse()
    if err != nil {
        return nil, fmt.Errorf("解析失败: %w", err)
    }
    
    // 解析后验证
    if !vector.IsValid() {
        return nil, fmt.Errorf("解析的向量无效")
    }
    
    return vector, nil
}
```

### 处理不同错误类型

```go
func handleParseErrors(vectorStr string) {
    parser := parser.NewCvss3xParser(vectorStr)
    vector, err := parser.Parse()
    
    if err != nil {
        switch e := err.(type) {
        case *parser.ParseError:
            fmt.Printf("解析错误: %s\n", e.Message)
            fmt.Printf("位置: %d\n", e.Position)
            fmt.Printf("输入: %s\n", e.Input)
        case *parser.ValidationError:
            fmt.Printf("验证错误: %s\n", e.Message)
            fmt.Printf("指标: %s\n", e.Metric)
            fmt.Printf("值: %s\n", e.Value)
        default:
            fmt.Printf("未知错误: %v\n", err)
        }
        return
    }
    
    fmt.Printf("解析成功: %s\n", vector.String())
}
```

### 验证示例

```go
func validateVector(vector *cvss.Cvss3x) []string {
    var issues []string
    
    // 检查版本
    if vector.MajorVersion != 3 {
        issues = append(issues, fmt.Sprintf("不支持的主版本: %d", vector.MajorVersion))
    }
    
    if vector.MinorVersion != 0 && vector.MinorVersion != 1 {
        issues = append(issues, fmt.Sprintf("不支持的次版本: %d", vector.MinorVersion))
    }
    
    // 检查基础指标
    if vector.Cvss3xBase == nil {
        issues = append(issues, "缺少基础指标")
    } else {
        if vector.Cvss3xBase.AttackVector == nil {
            issues = append(issues, "缺少攻击向量")
        }
        if vector.Cvss3xBase.AttackComplexity == nil {
            issues = append(issues, "缺少攻击复杂度")
        }
        // ... 检查其他必需指标
    }
    
    return issues
}
```

## 批量解析

### 处理多个向量

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
        return fmt.Sprintf("[%d] 成功: %s", r.Index, r.Input)
    }
    return fmt.Sprintf("[%d] 错误: %s - %v", r.Index, r.Input, r.Error)
}
```

### 并发批量处理

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

### 带统计信息的批量处理

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
    fmt.Printf("批量处理统计:\n")
    fmt.Printf("  总向量数: %d\n", s.Total)
    fmt.Printf("  成功: %d\n", s.Successful)
    fmt.Printf("  失败: %d\n", s.Failed)
    fmt.Printf("  成功率: %.1f%%\n", s.SuccessRate())
    
    if len(s.Errors) > 0 {
        fmt.Printf("  常见错误:\n")
        errorCounts := make(map[string]int)
        for _, err := range s.Errors {
            errorCounts[err.Error()]++
        }
        
        for errMsg, count := range errorCounts {
            fmt.Printf("    %s: %d 次\n", errMsg, count)
        }
    }
}
```

## 性能优化

### 解析器重用

```go
func optimizedParsing(vectors []string) []ParseResult {
    // 重用解析器实例
    parser := parser.NewCvss3xParser("")
    results := make([]ParseResult, len(vectors))
    
    for i, vectorStr := range vectors {
        result := ParseResult{
            Input: vectorStr,
            Index: i,
        }
        
        // 用新向量重用解析器
        parser.SetVector(vectorStr)
        vector, err := parser.Parse()
        
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

### 对象池模式

```go
var parserPool = sync.Pool{
    New: func() interface{} {
        return parser.NewCvss3xParser("")
    },
}

func parseWithPool(vectorStr string) (*cvss.Cvss3x, error) {
    parser := parserPool.Get().(*parser.Cvss3xParser)
    defer parserPool.Put(parser)
    
    parser.SetVector(vectorStr)
    return parser.Parse()
}

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
            
            parsed, err := parseWithPool(vector)
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

## 实际应用示例

### 文件处理

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
            continue // 跳过空行和注释
        }
        
        vector, err := robustParsing(line)
        if err != nil {
            fmt.Printf("第 %d 行错误: %v\n", lineNum, err)
            continue
        }
        
        fmt.Printf("第 %d 行: %s -> 有效\n", lineNum, vector.String())
    }
    
    return scanner.Err()
}
```

### CSV 处理

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
            continue // 跳过标题行
        }
        
        if len(record) < 1 {
            continue
        }
        
        vectorStr := record[0]
        vector, err := robustParsing(vectorStr)
        if err != nil {
            fmt.Printf("第 %d 行错误: %v\n", i+1, err)
            continue
        }
        
        fmt.Printf("第 %d 行: %s -> 有效\n", i+1, vector.String())
    }
    
    return nil
}
```

## 测试和验证

### 测试用例

```go
func runParsingTests() {
    testCases := []struct {
        name        string
        vector      string
        expectError bool
        description string
    }{
        {
            name:        "有效基础向量",
            vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: false,
            description: "标准高严重性向量",
        },
        {
            name:        "有效时间向量",
            vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
            expectError: false,
            description: "带时间指标的向量",
        },
        {
            name:        "无效版本",
            vector:      "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: true,
            description: "不支持的 CVSS 版本",
        },
        {
            name:        "缺少指标",
            vector:      "CVSS:3.1/AV:N/AC:L",
            expectError: true,
            description: "不完整的基础指标",
        },
        {
            name:        "无效指标值",
            vector:      "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: true,
            description: "无效的攻击向量值",
        },
    }
    
    for _, tc := range testCases {
        fmt.Printf("\n--- 测试: %s ---\n", tc.name)
        fmt.Printf("描述: %s\n", tc.description)
        fmt.Printf("向量: %s\n", tc.vector)
        
        vector, err := robustParsing(tc.vector)
        
        if tc.expectError {
            if err != nil {
                fmt.Printf("✓ 预期错误: %v\n", err)
            } else {
                fmt.Printf("✗ 预期错误但解析成功\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ 意外错误: %v\n", err)
            } else {
                fmt.Printf("✓ 解析成功: %s\n", vector.String())
            }
        }
    }
}
```

## 下一步

掌握向量解析后，您可以探索：

- [JSON 输出](/zh/examples/json) - 序列化解析的向量
- [距离计算](/zh/examples/distance) - 比较向量
- [高级示例](/zh/examples/edge-cases) - 复杂场景

## 相关文档

- [解析器 API 参考](/zh/api/parser/) - 详细解析器文档
- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 理解解析的数据
- [错误处理指南](/zh/api/cvss/) - 全面的错误处理
