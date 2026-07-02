# 环境指标示例

本示例演示如何使用 CVSS 环境指标，这些指标允许分析师根据受影响 IT 资产的重要性和特定环境中安全控制的有效性来定制 CVSS 分数。

## 概述

环境指标包含两个类别：

**环境需求:**
- **机密性需求 (CR)** - 机密性对组织的重要性
- **完整性需求 (IR)** - 完整性对组织的重要性  
- **可用性需求 (AR)** - 可用性对组织的重要性

**修改的基础指标:**
- 所有基础指标都可以修改以反映环境因素
- 前缀为"M"（例如，MAV、MAC、MPR等）

## 基本环境指标

### 理解环境影响

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 基础向量
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // 带需求的环境向量
    envVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
    
    // 带修改基础指标的环境向量
    modifiedVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"

    fmt.Println("=== 环境指标影响 ===")
    
    // 计算基础分数
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, err := baseParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    // 计算仅带需求的环境分数
    envParser := parser.NewCvss3xParser(envVector)
    envParsed, err := envParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    envCalc := cvss.NewCalculator(envParsed)
    envScore, _ := envCalc.Calculate()

    // 计算带修改指标的环境分数
    modParser := parser.NewCvss3xParser(modifiedVector)
    modParsed, err := modParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    modCalc := cvss.NewCalculator(modParsed)
    modScore, _ := modCalc.Calculate()

    fmt.Printf("基础向量: %s\n", baseVector)
    fmt.Printf("基础分数: %.1f (%s)\n", baseScore, baseCalc.GetSeverityRating(baseScore))
    
    fmt.Printf("\n环境（需求）: %s\n", envVector)
    fmt.Printf("环境分数: %.1f (%s)\n", envScore, envCalc.GetSeverityRating(envScore))
    fmt.Printf("分数变化: %+.1f 分\n", envScore-baseScore)
    
    fmt.Printf("\n环境（修改）: %s\n", modifiedVector)
    fmt.Printf("环境分数: %.1f (%s)\n", modScore, modCalc.GetSeverityRating(modScore))
    fmt.Printf("分数变化: %+.1f 分\n", modScore-baseScore)
}
```

### 环境指标分解

```go
func analyzeEnvironmentalMetrics(vector *cvss.Cvss3x) {
    if !vector.HasEnvironmentalMetrics() {
        fmt.Println("没有环境指标")
        return
    }

    fmt.Println("=== 环境指标分析 ===")
    
    env := vector.Cvss3xEnvironmental
    
    // 需求
    fmt.Println("需求:")
    if env.ConfidentialityRequirement != nil {
        fmt.Printf("  机密性需求: %s (%c) - %.2f\n",
            env.ConfidentialityRequirement.GetLongValue(),
            env.ConfidentialityRequirement.GetShortValue(),
            env.ConfidentialityRequirement.GetScore())
    }
    
    if env.IntegrityRequirement != nil {
        fmt.Printf("  完整性需求: %s (%c) - %.2f\n",
            env.IntegrityRequirement.GetLongValue(),
            env.IntegrityRequirement.GetShortValue(),
            env.IntegrityRequirement.GetScore())
    }
    
    if env.AvailabilityRequirement != nil {
        fmt.Printf("  可用性需求: %s (%c) - %.2f\n",
            env.AvailabilityRequirement.GetLongValue(),
            env.AvailabilityRequirement.GetShortValue(),
            env.AvailabilityRequirement.GetScore())
    }

    // 修改的基础指标
    fmt.Println("\n修改的基础指标:")
    if env.ModifiedAttackVector != nil {
        fmt.Printf("  修改的攻击向量: %s (%c)\n",
            env.ModifiedAttackVector.GetLongValue(),
            env.ModifiedAttackVector.GetShortValue())
    }
    
    if env.ModifiedAttackComplexity != nil {
        fmt.Printf("  修改的攻击复杂度: %s (%c)\n",
            env.ModifiedAttackComplexity.GetLongValue(),
            env.ModifiedAttackComplexity.GetShortValue())
    }
    
    // ... 其他修改指标
}
```

## 环境需求

### 需求级别影响

```go
func demonstrateRequirementLevels() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    requirements := []struct {
        name   string
        suffix string
        desc   string
    }{
        {"低需求", "/CR:L/IR:L/AR:L", "低重要性环境"},
        {"中等需求", "/CR:M/IR:M/AR:M", "中等重要性环境"},
        {"高需求", "/CR:H/IR:H/AR:H", "高重要性环境"},
        {"混合需求", "/CR:H/IR:M/AR:L", "混合重要性级别"},
    }

    fmt.Println("=== 环境需求影响 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    // 计算基础分数
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("基础分数: %.1f\n\n", baseScore)

    for _, req := range requirements {
        vectorStr := baseVector + req.suffix
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        change := score - baseScore

        fmt.Printf("%-12s: %.1f (%s) [%+.1f]\n", req.name, score, severity, change)
        fmt.Printf("  %s\n", req.desc)
        fmt.Printf("  向量: %s\n", vectorStr)
        fmt.Println()
    }
}
```

### 组织上下文示例

```go
func demonstrateOrganizationalContexts() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    contexts := []struct {
        organization string
        requirements string
        rationale    string
    }{
        {
            "金融机构",
            "/CR:H/IR:H/AR:H",
            "所有方面对监管合规和客户信任都至关重要",
        },
        {
            "电商平台",
            "/CR:H/IR:H/AR:H",
            "客户数据保护和交易完整性至关重要",
        },
        {
            "内部开发",
            "/CR:M/IR:M/AR:L",
            "具有中等敏感性的开发环境",
        },
        {
            "公共网站",
            "/CR:L/IR:M/AR:H",
            "公共信息，但可用性对业务至关重要",
        },
        {
            "研究环境",
            "/CR:H/IR:M/AR:L",
            "敏感研究数据，但可用性不太关键",
        },
    }

    fmt.Println("=== 组织上下文示例 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for _, context := range contexts {
        vectorStr := baseVector + context.requirements
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("组织: %s\n", context.organization)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  需求: %s\n", context.requirements)
        fmt.Printf("  理由: %s\n", context.rationale)
        fmt.Println()
    }
}
```

## 修改的基础指标

### 安全控制影响

```go
func demonstrateSecurityControls() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    controls := []struct {
        name     string
        modified string
        desc     string
    }{
        {
            "网络分段",
            "/MAV:L",
            "网络控制将攻击向量限制为本地",
        },
        {
            "需要身份验证",
            "/MPR:H",
            "强身份验证控制到位",
        },
        {
            "用户培训",
            "/MUI:R",
            "用户意识培训需要交互",
        },
        {
            "数据加密",
            "/MC:L",
            "加密降低机密性影响",
        },
        {
            "备份系统",
            "/MA:L",
            "冗余系统降低可用性影响",
        },
        {
            "组合控制",
            "/MAV:L/MPR:H/MUI:R/MC:L/MI:L/MA:L",
            "实施多种安全控制",
        },
    }

    fmt.Println("=== 安全控制影响 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    // 计算基础分数
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("基础分数: %.1f\n\n", baseScore)

    for _, control := range controls {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + control.modified
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        reduction := baseScore - score

        fmt.Printf("控制: %s\n", control.name)
        fmt.Printf("  分数: %.1f (%s) [%.1f 降低]\n", score, severity, reduction)
        fmt.Printf("  修改: %s\n", control.modified)
        fmt.Printf("  描述: %s\n", control.desc)
        fmt.Println()
    }
}
```

### 纵深防御分析

```go
func analyzeDefenseInDepth() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    layers := []struct {
        layer    string
        controls string
        desc     string
    }{
        {
            "无控制",
            "",
            "没有控制的基线漏洞",
        },
        {
            "边界安全",
            "/MAV:A",
            "防火墙限制访问到相邻网络",
        },
        {
            "访问控制",
            "/MAV:A/MPR:L",
            "需要基本身份验证",
        },
        {
            "增强身份验证",
            "/MAV:A/MPR:H",
            "实施多因素身份验证",
        },
        {
            "用户意识",
            "/MAV:A/MPR:H/MUI:R",
            "用户培训减少社会工程",
        },
        {
            "数据保护",
            "/MAV:A/MPR:H/MUI:R/MC:L/MI:L",
            "加密和完整性控制",
        },
        {
            "全面防御",
            "/MAV:L/MAC:H/MPR:H/MUI:R/MS:U/MC:L/MI:L/MA:L",
            "全面的安全控制",
        },
    }

    fmt.Println("=== 纵深防御分析 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for i, layer := range layers {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + layer.controls
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("层 %d: %s\n", i+1, layer.layer)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  控制: %s\n", layer.controls)
        fmt.Printf("  描述: %s\n", layer.desc)
        fmt.Println()
    }
}
```

## 环境分数计算

### 详细计算分解

```go
func explainEnvironmentalCalculation(vector *cvss.Cvss3x) {
    if !vector.HasEnvironmentalMetrics() {
        fmt.Println("没有环境指标可分析")
        return
    }

    calculator := cvss.NewCalculator(vector)
    
    // 获取各个分数
    baseScore, _ := calculator.GetBaseScore()
    envScore, _ := calculator.GetEnvironmentalScore()

    fmt.Println("=== 环境分数计算 ===")
    fmt.Printf("基础分数: %.1f\n", baseScore)
    
    env := vector.Cvss3xEnvironmental
    
    // 显示需求乘数
    crMultiplier := 1.0
    if env.ConfidentialityRequirement != nil {
        crMultiplier = env.ConfidentialityRequirement.GetScore()
    }
    
    irMultiplier := 1.0
    if env.IntegrityRequirement != nil {
        irMultiplier = env.IntegrityRequirement.GetScore()
    }
    
    arMultiplier := 1.0
    if env.AvailabilityRequirement != nil {
        arMultiplier = env.AvailabilityRequirement.GetScore()
    }

    fmt.Printf("\n需求乘数:\n")
    fmt.Printf("  机密性需求: %.1f\n", crMultiplier)
    fmt.Printf("  完整性需求: %.1f\n", irMultiplier)
    fmt.Printf("  可用性需求: %.1f\n", arMultiplier)
    
    // 检查修改的基础指标
    hasModified := env.ModifiedAttackVector != nil ||
                   env.ModifiedAttackComplexity != nil ||
                   env.ModifiedPrivilegesRequired != nil ||
                   env.ModifiedUserInteraction != nil ||
                   env.ModifiedScope != nil ||
                   env.ModifiedConfidentialityImpact != nil ||
                   env.ModifiedIntegrityImpact != nil ||
                   env.ModifiedAvailabilityImpact != nil

    if hasModified {
        fmt.Printf("\n存在修改的基础指标:\n")
        fmt.Printf("  使用修改指标计算环境分数\n")
    }
    
    fmt.Printf("\n最终环境分数: %.1f\n", envScore)
}
```

### 逐步计算

```go
func stepByStepEnvironmentalCalculation() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    envVector := baseVector + "/CR:H/IR:M/AR:L/MAV:L/MC:L"
    
    fmt.Println("=== 逐步环境计算 ===")
    fmt.Printf("向量: %s\n\n", envVector)
    
    vector, _ := parser.ParseString(envVector)
    
    calculator := cvss.NewCalculator(vector)
    
    // 步骤1：计算修改的基础分数
    fmt.Println("步骤1：计算修改的基础分数")
    fmt.Println("  使用提供的修改指标:")
    fmt.Println("  - 修改的攻击向量: 本地（而不是网络）")
    fmt.Println("  - 修改的机密性: 低（而不是高）")
    
    // 步骤2：应用环境需求
    fmt.Println("\n步骤2：应用环境需求")
    fmt.Println("  - 机密性需求: 高 (1.5x)")
    fmt.Println("  - 完整性需求: 中等 (1.0x)")
    fmt.Println("  - 可用性需求: 低 (0.5x)")
    
    // 步骤3：最终计算
    envScore, _ := calculator.GetEnvironmentalScore()
    fmt.Printf("\n步骤3：最终环境分数: %.1f\n", envScore)
}
```

## 实际应用

### 按环境的风险评估

```go
func assessRiskByEnvironment(baseVector string) {
    environments := []struct {
        name         string
        requirements string
        controls     string
        description  string
    }{
        {
            "生产DMZ",
            "/CR:H/IR:H/AR:H",
            "/MAV:A/MPR:L",
            "面向互联网的生产环境，具有基本控制",
        },
        {
            "内部生产",
            "/CR:H/IR:H/AR:H", 
            "/MAV:L/MPR:H/MUI:R",
            "具有强访问控制的内部生产",
        },
        {
            "开发环境",
            "/CR:M/IR:M/AR:L",
            "/MAV:L/MPR:L",
            "具有测试数据的开发环境",
        },
        {
            "隔离测试实验室",
            "/CR:L/IR:L/AR:L",
            "/MAV:L/MAC:H/MPR:H",
            "隔离的测试环境",
        },
    }

    fmt.Println("=== 按环境的风险评估 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    for _, env := range environments {
        vectorStr := baseVector + env.requirements + env.controls
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("环境: %s\n", env.name)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  需求: %s\n", env.requirements)
        fmt.Printf("  控制: %s\n", env.controls)
        fmt.Printf("  描述: %s\n", env.description)
        fmt.Println()
    }
}
```

### 控制有效性分析

```go
func analyzeControlEffectiveness(baseVector string) {
    controls := []struct {
        control     string
        investment  string
        reduction   string
        description string
    }{
        {
            "基本防火墙",
            "低",
            "/MAV:A",
            "网络边界保护",
        },
        {
            "WAF + IPS",
            "中等",
            "/MAV:A/MAC:H",
            "Web应用防火墙和入侵防护",
        },
        {
            "零信任",
            "高",
            "/MAV:L/MPR:H/MUI:R",
            "零信任架构实施",
        },
        {
            "完整安全栈",
            "非常高",
            "/MAV:L/MAC:H/MPR:H/MUI:R/MC:L/MI:L/MA:L",
            "全面的安全控制",
        },
    }

    fmt.Println("=== 控制有效性分析 ===")
    fmt.Printf("基础向量: %s\n\n", baseVector)

    // 计算基础分数
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("基础分数: %.1f\n\n", baseScore)

    for _, control := range controls {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + control.reduction
        
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        reduction := baseScore - score
        effectiveness := (reduction / baseScore) * 100

        fmt.Printf("控制: %s\n", control.control)
        fmt.Printf("  投资: %s\n", control.investment)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  降低: %.1f 分 (%.1f%% 有效)\n", reduction, effectiveness)
        fmt.Printf("  描述: %s\n", control.description)
        fmt.Println()
    }
}
```

## 测试和验证

### 环境指标验证

```go
func validateEnvironmentalMetrics(vector *cvss.Cvss3x) []string {
    var issues []string

    if !vector.HasEnvironmentalMetrics() {
        return issues
    }

    env := vector.Cvss3xEnvironmental

    // 验证需求指标
    if env.ConfidentialityRequirement != nil {
        value := env.ConfidentialityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("无效的机密性需求: %c", value))
        }
    }

    if env.IntegrityRequirement != nil {
        value := env.IntegrityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("无效的完整性需求: %c", value))
        }
    }

    if env.AvailabilityRequirement != nil {
        value := env.AvailabilityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("无效的可用性需求: %c", value))
        }
    }

    // 验证修改的基础指标（类似基础指标验证）
    // ... 额外的验证逻辑

    return issues
}
```

## 下一步

掌握环境指标后，您可以探索：

- [向量比较](/zh/examples/comparison) - 比较不同的环境配置
- [严重性级别](/zh/examples/severity) - 理解不同上下文中的严重性
- [高级示例](/zh/examples/edge-cases) - 复杂的环境场景

## 相关文档

- [环境指标 API](/zh/api/cvss/calculator) - 详细 API 参考
- [CVSS 规范](https://www.first.org/cvss/) - 官方 CVSS 文档
- [风险评估指南](/zh/examples/risk-assessment) - 全面的风险评估示例
