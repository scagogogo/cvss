# 时间指标示例

本示例演示如何使用 CVSS 时间指标，这些指标反映随时间变化的漏洞特征。

## 概述

时间指标允许您根据以下因素调整 CVSS 分数：

- **漏洞利用代码成熟度 (E)** - 漏洞利用代码的可用性和复杂程度
- **修复级别 (RL)** - 修复或变通方法的可用性
- **报告可信度 (RC)** - 对漏洞报告的信心程度

这些指标有助于通过考虑当前威胁环境提供更准确的风险评估。

## 时间指标如何演变

三个时间指标刻画漏洞的生命周期。随着利用手段成熟、修复发布，时间评分会随之变动 —— 始终**不超过基础评分**：

```mermaid
stateDiagram-v2
    [*] --> 已披露
    已披露 --> PoC: 出现利用代码 (E:P)
    PoC --> 可用利用: 可靠利用 (E:F)
    可用利用 --> 武器化: 大规模利用 (E:H)

    已披露 --> 变通方案: 缓解措施 (RL:W)
    变通方案 --> 临时修复: 临时补丁 (RL:T)
    临时修复 --> 已修复: 官方补丁 (RL:O)
    已修复 --> [*]

    note right of 武器化
        E 抬高时间评分
        使其趋近基础评分
    end note
    note right of 已修复
        RL:O 降低时间评分
    end note
```

## 基本时间指标

### 理解时间指标

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 不带时间指标的基础向量
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // 带时间指标的相同向量
    temporalVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"

    fmt.Println("=== 时间指标影响 ===")
    
    // 解析并计算基础分数
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, err := baseParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    // 解析并计算时间分数
    temporalParser := parser.NewCvss3xParser(temporalVector)
    temporalParsed, err := temporalParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    temporalCalc := cvss.NewCalculator(temporalParsed)
    temporalScore, _ := temporalCalc.Calculate()

    fmt.Printf("基础向量: %s\n", baseVector)
    fmt.Printf("基础分数: %.1f (%s)\n", baseScore, baseCalc.GetSeverityRating(baseScore))
    fmt.Printf("\n时间向量: %s\n", temporalVector)
    fmt.Printf("时间分数: %.1f (%s)\n", temporalScore, temporalCalc.GetSeverityRating(temporalScore))
    fmt.Printf("分数降低: %.1f 分\n", baseScore-temporalScore)
}
```

### 时间指标分解

```go
func analyzeTemporalMetrics(vector *cvss.Cvss3x) {
    if !vector.HasTemporal() {
        fmt.Println("没有时间指标")
        return
    }

    fmt.Println("=== 时间指标分析 ===")
    
    temporal := vector.Cvss3xTemporal
    
    // 漏洞利用代码成熟度
    if temporal.ExploitCodeMaturity != nil {
        fmt.Printf("漏洞利用代码成熟度: %s (%c)\n",
            temporal.ExploitCodeMaturity.GetLongValue(),
            temporal.ExploitCodeMaturity.GetShortValue())
        fmt.Printf("  分数乘数: %.2f\n", temporal.ExploitCodeMaturity.GetScore())
        fmt.Printf("  描述: %s\n", temporal.ExploitCodeMaturity.GetDescription())
    }

    // 修复级别
    if temporal.RemediationLevel != nil {
        fmt.Printf("\n修复级别: %s (%c)\n",
            temporal.RemediationLevel.GetLongValue(),
            temporal.RemediationLevel.GetShortValue())
        fmt.Printf("  分数乘数: %.2f\n", temporal.RemediationLevel.GetScore())
        fmt.Printf("  描述: %s\n", temporal.RemediationLevel.GetDescription())
    }

    // 报告可信度
    if temporal.ReportConfidence != nil {
        fmt.Printf("\n报告可信度: %s (%c)\n",
            temporal.ReportConfidence.GetLongValue(),
            temporal.ReportConfidence.GetShortValue())
        fmt.Printf("  分数乘数: %.2f\n", temporal.ReportConfidence.GetScore())
        fmt.Printf("  描述: %s\n", temporal.ReportConfidence.GetDescription())
    }
}
```

## 漏洞利用代码成熟度 (E)

### 不同成熟度级别

```go
func demonstrateExploitMaturity() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    exploitLevels := map[string]string{
        "未定义":      baseVector + "/E:X",
        "未证实":      baseVector + "/E:U", 
        "概念验证":    baseVector + "/E:P",
        "功能性":      baseVector + "/E:F",
        "高成熟度":    baseVector + "/E:H",
    }

    fmt.Println("=== 漏洞利用代码成熟度影响 ===")
    
    for level, vectorStr := range exploitLevels {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()

        fmt.Printf("%-12s: %.1f", level, score)
        if vector.HasTemporal() && vector.Cvss3xTemporal.ExploitCodeMaturity != nil {
            multiplier := vector.Cvss3xTemporal.ExploitCodeMaturity.GetScore()
            fmt.Printf(" (乘数: %.2f)", multiplier)
        }
        fmt.Println()
    }
}
```

### 漏洞利用演化跟踪

```go
func trackExploitEvolution(baseVector string) {
    stages := []struct {
        stage       string
        exploitCode string
        description string
    }{
        {"发现阶段", "E:X", "漏洞刚被发现"},
        {"研究阶段", "E:U", "研究人员正在调查"},
        {"PoC发布", "E:P", "概念验证代码可用"},
        {"工作漏洞利用", "E:F", "功能性漏洞利用代码可用"},
        {"武器化", "E:H", "复杂的漏洞利用工具可用"},
    }

    fmt.Println("=== 漏洞利用演化时间线 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for i, stage := range stages {
        vectorStr := baseVector + "/" + stage.exploitCode
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("阶段 %d: %s\n", i+1, stage.stage)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  描述: %s\n", stage.description)
        fmt.Println()
    }
}
```

## 修复级别 (RL)

### 修复进展

```go
func demonstrateRemediationLevels() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    remediationLevels := map[string]string{
        "未定义":    baseVector + "/RL:X",
        "官方修复":  baseVector + "/RL:O",
        "临时修复":  baseVector + "/RL:T",
        "变通方法":  baseVector + "/RL:W",
        "不可用":    baseVector + "/RL:U",
    }

    fmt.Println("=== 修复级别影响 ===")
    
    for level, vectorStr := range remediationLevels {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()

        fmt.Printf("%-8s: %.1f", level, score)
        if vector.HasTemporal() && vector.Cvss3xTemporal.RemediationLevel != nil {
            multiplier := vector.Cvss3xTemporal.RemediationLevel.GetScore()
            fmt.Printf(" (乘数: %.2f)", multiplier)
        }
        fmt.Println()
    }
}
```

### 修复时间线

```go
func trackRemediationProgress(baseVector string) {
    timeline := []struct {
        day         int
        remediation string
        description string
    }{
        {0, "RL:U", "漏洞披露，无修复可用"},
        {7, "RL:W", "变通方法发布"},
        {14, "RL:T", "临时补丁发布"},
        {30, "RL:O", "官方修复发布"},
    }

    fmt.Println("=== 修复时间线 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for _, entry := range timeline {
        vectorStr := baseVector + "/" + entry.remediation
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("第 %d 天: %s\n", entry.day, entry.description)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Println()
    }
}
```

## 报告可信度 (RC)

### 可信度级别

```go
func demonstrateReportConfidence() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    confidenceLevels := map[string]string{
        "未定义": baseVector + "/RC:X",
        "未知":   baseVector + "/RC:U",
        "合理":   baseVector + "/RC:R", 
        "已确认": baseVector + "/RC:C",
    }

    fmt.Println("=== 报告可信度影响 ===")
    
    for level, vectorStr := range confidenceLevels {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()

        fmt.Printf("%-8s: %.1f", level, score)
        if vector.HasTemporal() && vector.Cvss3xTemporal.ReportConfidence != nil {
            multiplier := vector.Cvss3xTemporal.ReportConfidence.GetScore()
            fmt.Printf(" (乘数: %.2f)", multiplier)
        }
        fmt.Println()
    }
}
```

### 可信度演化

```go
func trackConfidenceEvolution(baseVector string) {
    stages := []struct {
        stage       string
        confidence  string
        description string
    }{
        {"初始报告", "RC:U", "未验证的漏洞报告"},
        {"分析阶段", "RC:R", "分析后的合理可信度"},
        {"复现验证", "RC:C", "漏洞已确认并复现"},
    }

    fmt.Println("=== 可信度演化 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for i, stage := range stages {
        vectorStr := baseVector + "/" + stage.confidence
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("阶段 %d: %s\n", i+1, stage.stage)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  描述: %s\n", stage.description)
        fmt.Println()
    }
}
```

## 综合时间分析

### 完整时间场景

```go
func analyzeTemporalScenarios() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    scenarios := []struct {
        name        string
        temporal    string
        description string
    }{
        {
            "最坏情况",
            "/E:H/RL:U/RC:C",
            "高漏洞利用成熟度，无修复，已确认",
        },
        {
            "最好情况", 
            "/E:U/RL:O/RC:R",
            "未证实漏洞利用，官方修复，合理可信度",
        },
        {
            "典型情况",
            "/E:F/RL:T/RC:C", 
            "功能性漏洞利用，临时修复，已确认",
        },
        {
            "早期阶段",
            "/E:P/RL:W/RC:R",
            "PoC可用，存在变通方法，合理可信度",
        },
    }

    fmt.Println("=== 时间场景分析 ===")
    fmt.Printf("基础向量: %s\n", baseVector)
    
    baseParser := parser.NewCvss3xParser(baseVector)
    baseVector_parsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseVector_parsed)
    baseScore, _ := baseCalc.Calculate()
    
    fmt.Printf("基础分数: %.1f\n\n", baseScore)

    for _, scenario := range scenarios {
        vectorStr := baseVector + scenario.temporal
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        reduction := baseScore - score

        fmt.Printf("场景: %s\n", scenario.name)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  降低: %.1f 分\n", reduction)
        fmt.Printf("  描述: %s\n", scenario.description)
        fmt.Println()
    }
}
```

### 时间分数计算

```go
func explainTemporalCalculation(vector *cvss.Cvss3x) {
    if !vector.HasTemporal() {
        fmt.Println("没有时间指标可分析")
        return
    }

    calculator := cvss.NewCalculator(vector)
    
    // 获取各个分数
    baseScore, _ := calculator.CalculateBaseScore()
    temporalScore, _ := calculator.CalculateTemporalScore()

    fmt.Println("=== 时间分数计算 ===")
    fmt.Printf("基础分数: %.1f\n", baseScore)
    
    temporal := vector.Cvss3xTemporal
    
    // 显示乘数
    eMultiplier := 1.0
    if temporal.ExploitCodeMaturity != nil {
        eMultiplier = temporal.ExploitCodeMaturity.GetScore()
    }
    
    rlMultiplier := 1.0
    if temporal.RemediationLevel != nil {
        rlMultiplier = temporal.RemediationLevel.GetScore()
    }
    
    rcMultiplier := 1.0
    if temporal.ReportConfidence != nil {
        rcMultiplier = temporal.ReportConfidence.GetScore()
    }

    fmt.Printf("\n时间乘数:\n")
    fmt.Printf("  漏洞利用代码成熟度: %.2f\n", eMultiplier)
    fmt.Printf("  修复级别: %.2f\n", rlMultiplier)
    fmt.Printf("  报告可信度: %.2f\n", rcMultiplier)
    
    combinedMultiplier := eMultiplier * rlMultiplier * rcMultiplier
    fmt.Printf("  组合乘数: %.3f\n", combinedMultiplier)
    
    fmt.Printf("\n计算:\n")
    fmt.Printf("  时间分数 = 基础分数 × 组合乘数\n")
    fmt.Printf("  时间分数 = %.1f × %.3f = %.1f\n", 
        baseScore, combinedMultiplier, temporalScore)
}
```

## 实际应用

### 随时间的风险评估

```go
func assessRiskOverTime(baseVector string, days int) {
    fmt.Println("=== 风险评估时间线 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    timeline := []struct {
        day     int
        metrics string
        event   string
    }{
        {0, "/E:X/RL:U/RC:U", "漏洞发现"},
        {1, "/E:U/RL:U/RC:R", "初始分析完成"},
        {3, "/E:P/RL:U/RC:C", "PoC发布"},
        {7, "/E:P/RL:W/RC:C", "变通方法可用"},
        {14, "/E:F/RL:W/RC:C", "工作漏洞利用发布"},
        {21, "/E:F/RL:T/RC:C", "临时补丁可用"},
        {30, "/E:H/RL:O/RC:C", "官方修复发布，漏洞利用武器化"},
    }

    for _, entry := range timeline {
        if entry.day > days {
            break
        }

        vectorStr := baseVector + entry.metrics
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("第 %2d 天: %s\n", entry.day, entry.event)
        fmt.Printf("        分数: %.1f (%s)\n", score, severity)
        fmt.Printf("        向量: %s\n", vectorStr)
        fmt.Println()
    }
}
```

### 漏洞生命周期管理

```go
func manageVulnerabilityLifecycle(baseVector string) {
    phases := []struct {
        phase   string
        metrics string
        actions []string
    }{
        {
            "发现阶段",
            "/E:X/RL:U/RC:U",
            []string{"验证漏洞", "评估影响", "通知利益相关者"},
        },
        {
            "分析阶段", 
            "/E:U/RL:U/RC:R",
            []string{"开发变通方法", "制定修复计划", "监控漏洞利用"},
        },
        {
            "利用阶段",
            "/E:F/RL:W/RC:C", 
            []string{"部署变通方法", "加速补丁开发", "增强监控"},
        },
        {
            "修复阶段",
            "/E:F/RL:O/RC:C",
            []string{"部署补丁", "验证修复", "更新文档"},
        },
    }

    fmt.Println("=== 漏洞生命周期管理 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for i, phase := range phases {
        vectorStr := baseVector + phase.metrics
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("阶段 %d: %s\n", i+1, phase.phase)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Printf("  行动:\n")
        for _, action := range phase.actions {
            fmt.Printf("    - %s\n", action)
        }
        fmt.Println()
    }
}
```

## 测试和验证

### 时间指标验证

```go
func validateTemporalMetrics(vector *cvss.Cvss3x) []string {
    var issues []string

    if !vector.HasTemporal() {
        return issues
    }

    temporal := vector.Cvss3xTemporal

    // 验证漏洞利用代码成熟度
    if temporal.ExploitCodeMaturity != nil {
        value := temporal.ExploitCodeMaturity.GetShortValue()
        if value != 'X' && value != 'U' && value != 'P' && value != 'F' && value != 'H' {
            issues = append(issues, fmt.Sprintf("无效的漏洞利用代码成熟度: %c", value))
        }
    }

    // 验证修复级别
    if temporal.RemediationLevel != nil {
        value := temporal.RemediationLevel.GetShortValue()
        if value != 'X' && value != 'O' && value != 'T' && value != 'W' && value != 'U' {
            issues = append(issues, fmt.Sprintf("无效的修复级别: %c", value))
        }
    }

    // 验证报告可信度
    if temporal.ReportConfidence != nil {
        value := temporal.ReportConfidence.GetShortValue()
        if value != 'X' && value != 'U' && value != 'R' && value != 'C' {
            issues = append(issues, fmt.Sprintf("无效的报告可信度: %c", value))
        }
    }

    return issues
}
```

## 下一步

掌握时间指标后，您可以探索：

- [环境指标](/zh/examples/environmental) - 特定上下文评分
- [向量比较](/zh/examples/comparison) - 比较不同向量
- [高级示例](/zh/examples/edge-cases) - 复杂场景

## 相关文档

- [时间指标 API](/zh/api/cvss/calculator) - 详细 API 参考
- [CVSS 规范](https://www.first.org/cvss/) - 官方 CVSS 文档
- [漏洞管理](/zh/examples/risk-assessment) - 生命周期管理示例
