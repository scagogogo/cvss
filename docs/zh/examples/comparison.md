# 向量比较示例

本示例演示比较 CVSS 向量的各种方法，包括并排分析、指标级比较和自动化比较工具。

## 概述

向量比较对以下方面至关重要：

- 漏洞优先级排序
- 风险评估验证
- 安全控制有效性测量
- 漏洞演化跟踪
- 合规报告

## 基本向量比较

### 简单并排比较

```go
package main

import (
    "fmt"
    "log"
    "sort"
    "strings"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    }

    fmt.Println("=== 基本向量比较 ===")
    
    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    scores := make([]float64, len(vectors))
    severities := make([]string, len(vectors))

    // 解析所有向量并计算分数
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            log.Fatal(err)
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        parsedVectors[i] = vector
        scores[i] = score
        severities[i] = severity

        fmt.Printf("向量 %d: %s\n", i+1, vectorStr)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Println()
    }

    // 找到最高和最低分数
    maxScore, maxIndex := findMaxScore(scores)
    minScore, minIndex := findMinScore(scores)

    fmt.Printf("最高风险: 向量 %d (%.1f - %s)\n", maxIndex+1, maxScore, severities[maxIndex])
    fmt.Printf("最低风险: 向量 %d (%.1f - %s)\n", minIndex+1, minScore, severities[minIndex])
}

func findMaxScore(scores []float64) (float64, int) {
    max := scores[0]
    index := 0
    for i, score := range scores {
        if score > max {
            max = score
            index = i
        }
    }
    return max, index
}

func findMinScore(scores []float64) (float64, int) {
    min := scores[0]
    index := 0
    for i, score := range scores {
        if score < min {
            min = score
            index = i
        }
    }
    return min, index
}
```

### 详细指标比较

```go
func compareVectorsDetailed(v1, v2 *cvss.Cvss3x) {
    fmt.Println("=== 详细向量比较 ===")
    fmt.Printf("向量 1: %s\n", v1.String())
    fmt.Printf("向量 2: %s\n", v2.String())
    fmt.Println()

    // 比较基础指标
    fmt.Println("基础指标比较:")
    compareMetric("攻击向量", 
        v1.Cvss3xBase.AttackVector, 
        v2.Cvss3xBase.AttackVector)
    compareMetric("攻击复杂度", 
        v1.Cvss3xBase.AttackComplexity, 
        v2.Cvss3xBase.AttackComplexity)
    compareMetric("所需权限", 
        v1.Cvss3xBase.PrivilegesRequired, 
        v2.Cvss3xBase.PrivilegesRequired)
    compareMetric("用户交互", 
        v1.Cvss3xBase.UserInteraction, 
        v2.Cvss3xBase.UserInteraction)
    compareMetric("作用域", 
        v1.Cvss3xBase.Scope, 
        v2.Cvss3xBase.Scope)
    compareMetric("机密性影响", 
        v1.Cvss3xBase.Confidentiality, 
        v2.Cvss3xBase.Confidentiality)
    compareMetric("完整性影响", 
        v1.Cvss3xBase.Integrity, 
        v2.Cvss3xBase.Integrity)
    compareMetric("可用性影响", 
        v1.Cvss3xBase.Availability, 
        v2.Cvss3xBase.Availability)

    // 比较分数
    calc1 := cvss.NewCalculator(v1)
    calc2 := cvss.NewCalculator(v2)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("\n分数比较:\n")
    fmt.Printf("  向量 1: %.1f (%s)\n", score1, calc1.GetSeverityRating(score1))
    fmt.Printf("  向量 2: %.1f (%s)\n", score2, calc2.GetSeverityRating(score2))
    fmt.Printf("  差异: %.1f 分\n", abs(score1-score2))
    
    if score1 > score2 {
        fmt.Printf("  向量 1 风险更高，高出 %.1f 分\n", score1-score2)
    } else if score2 > score1 {
        fmt.Printf("  向量 2 风险更高，高出 %.1f 分\n", score2-score1)
    } else {
        fmt.Printf("  向量风险分数相等\n")
    }
}

func compareMetric(name string, m1, m2 vector.Vector) {
    if m1.GetShortValue() == m2.GetShortValue() {
        fmt.Printf("  %-15s: %s (相同)\n", name, m1.GetLongValue())
    } else {
        fmt.Printf("  %-15s: %s vs %s\n", name, m1.GetLongValue(), m2.GetLongValue())
        
        score1 := m1.GetScore()
        score2 := m2.GetScore()
        if score1 > score2 {
            fmt.Printf("  %15s  向量 1 更高 (%.2f vs %.2f)\n", "", score1, score2)
        } else if score2 > score1 {
            fmt.Printf("  %15s  向量 2 更高 (%.2f vs %.2f)\n", "", score2, score1)
        }
    }
}

func abs(x float64) float64 {
    if x < 0 {
        return -x
    }
    return x
}
```

## 比较矩阵

### 多向量比较矩阵

```go
func createComparisonMatrix(vectors []*cvss.Cvss3x) {
    fmt.Println("=== 向量比较矩阵 ===")
    
    // 计算所有向量的分数
    scores := make([]float64, len(vectors))
    severities := make([]string, len(vectors))
    
    for i, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        scores[i] = score
        severities[i] = severity
    }

    // 打印标题
    fmt.Printf("%10s", "")
    for i := range vectors {
        fmt.Printf("%12s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    // 打印分数
    fmt.Printf("%10s", "分数")
    for _, score := range scores {
        fmt.Printf("%12.1f", score)
    }
    fmt.Println()

    fmt.Printf("%10s", "严重性")
    for _, severity := range severities {
        fmt.Printf("%12s", severity)
    }
    fmt.Println()

    // 打印比较矩阵
    fmt.Println("\n分数差异:")
    fmt.Printf("%10s", "")
    for i := range vectors {
        fmt.Printf("%12s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    for i, score1 := range scores {
        fmt.Printf("%10s", fmt.Sprintf("V%d", i+1))
        for _, score2 := range scores {
            diff := score1 - score2
            if diff == 0 {
                fmt.Printf("%12s", "0.0")
            } else {
                fmt.Printf("%12.1f", diff)
            }
        }
        fmt.Println()
    }
}
```

### 指标级比较矩阵

```go
func createMetricComparisonMatrix(vectors []*cvss.Cvss3x) {
    fmt.Println("=== 指标比较矩阵 ===")
    
    metrics := []struct {
        name string
        getter func(*cvss.Cvss3x) vector.Vector
    }{
        {"AV", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.AttackVector }},
        {"AC", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.AttackComplexity }},
        {"PR", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.PrivilegesRequired }},
        {"UI", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.UserInteraction }},
        {"S", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.Scope }},
        {"C", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.Confidentiality }},
        {"I", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.Integrity }},
        {"A", func(v *cvss.Cvss3x) vector.Vector { return v.Cvss3xBase.Availability }},
    }

    // 打印标题
    fmt.Printf("%8s", "指标")
    for i := range vectors {
        fmt.Printf("%8s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    // 打印每个指标
    for _, metric := range metrics {
        fmt.Printf("%8s", metric.name)
        for _, vector := range vectors {
            m := metric.getter(vector)
            fmt.Printf("%8c", m.GetShortValue())
        }
        fmt.Println()
    }

    // 打印分数
    fmt.Printf("%8s", "分数")
    for _, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        fmt.Printf("%8.1f", score)
    }
    fmt.Println()
}
```

## 漏洞演化跟踪

### 版本比较

```go
func trackVulnerabilityEvolution() {
    versions := []struct {
        version string
        vector  string
        changes string
    }{
        {
            "初始报告",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "初始评估",
        },
        {
            "分析后",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "需要身份验证，复杂度更高",
        },
        {
            "有变通方法",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:P/RL:W/RC:C",
            "变通方法降低影响，PoC可用",
        },
        {
            "补丁后",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:F/RL:O/RC:C",
            "官方修复可用，漏洞利用功能性",
        },
    }

    fmt.Println("=== 漏洞演化跟踪 ===")
    
    var previousScore float64
    
    for i, version := range versions {
        vector, _ := parser.ParseString(version.vector)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("版本 %d: %s\n", i+1, version.version)
        fmt.Printf("  向量: %s\n", version.vector)
        fmt.Printf("  分数: %.1f (%s)\n", score, severity)
        fmt.Printf("  变化: %s\n", version.changes)
        
        if i > 0 {
            change := score - previousScore
            if change > 0 {
                fmt.Printf("  分数变化: +%.1f (风险增加)\n", change)
            } else if change < 0 {
                fmt.Printf("  分数变化: %.1f (风险降低)\n", change)
            } else {
                fmt.Printf("  分数变化: 0.0 (无变化)\n")
            }
        }
        
        previousScore = score
        fmt.Println()
    }
}
```

### 变化影响分析

```go
func analyzeChangeImpact(original, modified *cvss.Cvss3x) {
    fmt.Println("=== 变化影响分析 ===")
    
    calc1 := cvss.NewCalculator(original)
    calc2 := cvss.NewCalculator(modified)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("原始: %s (%.1f)\n", original.String(), score1)
    fmt.Printf("修改: %s (%.1f)\n", modified.String(), score2)
    fmt.Printf("分数变化: %.1f 分\n", score2-score1)
    
    // 分析哪些指标发生了变化
    changes := findMetricChanges(original, modified)
    
    if len(changes) == 0 {
        fmt.Println("未检测到指标变化")
    } else {
        fmt.Printf("\n指标变化 (%d):\n", len(changes))
        for _, change := range changes {
            fmt.Printf("  %s: %s → %s\n", change.Metric, change.From, change.To)
            
            impact := change.ScoreImpact
            if impact > 0 {
                fmt.Printf("    影响: +%.2f (增加风险)\n", impact)
            } else if impact < 0 {
                fmt.Printf("    影响: %.2f (降低风险)\n", impact)
            } else {
                fmt.Printf("    影响: 0.00 (无分数变化)\n")
            }
        }
    }
}

type MetricChange struct {
    Metric      string
    From        string
    To          string
    ScoreImpact float64
}

func findMetricChanges(v1, v2 *cvss.Cvss3x) []MetricChange {
    var changes []MetricChange
    
    // 比较基础指标
    if v1.Cvss3xBase.AttackVector.GetShortValue() != v2.Cvss3xBase.AttackVector.GetShortValue() {
        changes = append(changes, MetricChange{
            Metric: "攻击向量",
            From:   v1.Cvss3xBase.AttackVector.GetLongValue(),
            To:     v2.Cvss3xBase.AttackVector.GetLongValue(),
            ScoreImpact: v2.Cvss3xBase.AttackVector.GetScore() - v1.Cvss3xBase.AttackVector.GetScore(),
        })
    }
    
    // ... 类似地比较其他指标
    
    return changes
}
```

## 风险优先级排序

### 多标准比较

```go
func prioritizeVulnerabilities(vectors []*cvss.Cvss3x) []VulnerabilityRanking {
    var rankings []VulnerabilityRanking
    
    for i, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        
        ranking := VulnerabilityRanking{
            Index:    i,
            Vector:   vector,
            Score:    score,
            Severity: calculator.GetSeverityRating(score),
        }
        
        // 计算额外的风险因素
        ranking.ExploitabilityScore = calculateExploitabilityScore(vector)
        ranking.ImpactScore = calculateImpactScore(vector)
        ranking.RiskFactors = analyzeRiskFactors(vector)
        
        rankings = append(rankings, ranking)
    }
    
    // 按分数排序（最高在前）
    sort.Slice(rankings, func(i, j int) bool {
        return rankings[i].Score > rankings[j].Score
    })
    
    return rankings
}

type VulnerabilityRanking struct {
    Index               int
    Vector              *cvss.Cvss3x
    Score               float64
    Severity            string
    ExploitabilityScore float64
    ImpactScore         float64
    RiskFactors         []string
}

func calculateExploitabilityScore(vector *cvss.Cvss3x) float64 {
    // 简化的可利用性计算
    av := vector.Cvss3xBase.AttackVector.GetScore()
    ac := vector.Cvss3xBase.AttackComplexity.GetScore()
    pr := vector.Cvss3xBase.PrivilegesRequired.GetScore()
    ui := vector.Cvss3xBase.UserInteraction.GetScore()
    
    return 8.22 * av * ac * pr * ui
}

func calculateImpactScore(vector *cvss.Cvss3x) float64 {
    // 简化的影响计算
    c := vector.Cvss3xBase.Confidentiality.GetScore()
    i := vector.Cvss3xBase.Integrity.GetScore()
    a := vector.Cvss3xBase.Availability.GetScore()
    
    return 6.42 * (1 - (1-c) * (1-i) * (1-a))
}

func analyzeRiskFactors(vector *cvss.Cvss3x) []string {
    var factors []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        factors = append(factors, "网络可访问")
    }
    
    if vector.Cvss3xBase.AttackComplexity.GetShortValue() == 'L' {
        factors = append(factors, "低攻击复杂度")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        factors = append(factors, "无需权限")
    }
    
    if vector.Cvss3xBase.UserInteraction.GetShortValue() == 'N' {
        factors = append(factors, "无需用户交互")
    }
    
    return factors
}

func printVulnerabilityRankings(rankings []VulnerabilityRanking) {
    fmt.Println("=== 漏洞优先级排序 ===")
    
    for i, ranking := range rankings {
        fmt.Printf("排名 %d: 向量 %d\n", i+1, ranking.Index+1)
        fmt.Printf("  分数: %.1f (%s)\n", ranking.Score, ranking.Severity)
        fmt.Printf("  可利用性: %.1f\n", ranking.ExploitabilityScore)
        fmt.Printf("  影响: %.1f\n", ranking.ImpactScore)
        fmt.Printf("  向量: %s\n", ranking.Vector.String())
        
        if len(ranking.RiskFactors) > 0 {
            fmt.Printf("  风险因素: %s\n", strings.Join(ranking.RiskFactors, ", "))
        }
        fmt.Println()
    }
}
```

### 比较风险概况

```go
func compareRiskProfiles(vectors []*cvss.Cvss3x) {
    fmt.Println("=== 比较风险概况 ===")
    
    profiles := make([]RiskProfile, len(vectors))
    
    for i, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        
        profiles[i] = RiskProfile{
            Index:        i,
            Score:        score,
            Severity:     calculator.GetSeverityRating(score),
            AttackVector: vector.Cvss3xBase.AttackVector.GetLongValue(),
            Complexity:   vector.Cvss3xBase.AttackComplexity.GetLongValue(),
            Privileges:   vector.Cvss3xBase.PrivilegesRequired.GetLongValue(),
            Interaction:  vector.Cvss3xBase.UserInteraction.GetLongValue(),
            CIAImpact:    fmt.Sprintf("%c/%c/%c",
                vector.Cvss3xBase.Confidentiality.GetShortValue(),
                vector.Cvss3xBase.Integrity.GetShortValue(),
                vector.Cvss3xBase.Availability.GetShortValue()),
        }
    }
    
    // 打印比较表
    fmt.Printf("%-8s %-8s %-12s %-12s %-12s %-12s %-12s %-8s\n",
        "向量", "分数", "严重性", "攻击向量", "复杂度", "权限", "交互", "C/I/A")
    fmt.Println(strings.Repeat("-", 100))
    
    for _, profile := range profiles {
        fmt.Printf("%-8d %-8.1f %-12s %-12s %-12s %-12s %-12s %-8s\n",
            profile.Index+1,
            profile.Score,
            profile.Severity,
            profile.AttackVector,
            profile.Complexity,
            profile.Privileges,
            profile.Interaction,
            profile.CIAImpact)
    }
}

type RiskProfile struct {
    Index        int
    Score        float64
    Severity     string
    AttackVector string
    Complexity   string
    Privileges   string
    Interaction  string
    CIAImpact    string
}
```

## 自动化比较工具

### 批量比较

```go
func batchCompareVectors(vectors []string) {
    fmt.Println("=== 批量向量比较 ===")
    
    results := make([]ComparisonResult, len(vectors))
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)

        result := ComparisonResult{
            Index:  i,
            Vector: vectorStr,
        }
        
        if err != nil {
            result.Error = err
        } else {
            calculator := cvss.NewCalculator(vector)
            score, _ := calculator.Calculate()
            
            result.Score = score
            result.Severity = calculator.GetSeverityRating(score)
            result.Parsed = vector
        }
        
        results[i] = result
    }
    
    // 按分数排序
    sort.Slice(results, func(i, j int) bool {
        return results[i].Score > results[j].Score
    })
    
    // 打印结果
    for i, result := range results {
        fmt.Printf("排名 %d: ", i+1)
        if result.Error != nil {
            fmt.Printf("错误 - %s: %v\n", result.Vector, result.Error)
        } else {
            fmt.Printf("%.1f (%s) - %s\n", result.Score, result.Severity, result.Vector)
        }
    }
}

type ComparisonResult struct {
    Index    int
    Vector   string
    Score    float64
    Severity string
    Parsed   *cvss.Cvss3x
    Error    error
}
```

## 测试和验证

### 比较准确性测试

```go
func testComparisonAccuracy() {
    testCases := []struct {
        name     string
        vector1  string
        vector2  string
        expected string // "higher", "lower", "equal"
    }{
        {
            "网络 vs 本地",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "higher",
        },
        {
            "高 vs 低影响",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "higher",
        },
        {
            "相同向量",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "equal",
        },
    }

    fmt.Println("=== 比较准确性测试 ===")

    for _, tc := range testCases {
        fmt.Printf("\n测试: %s\n", tc.name)
        
        parser1 := parser.NewCvss3xParser(tc.vector1)
        vector1, _ := parser1.Parse()
        
        parser2 := parser.NewCvss3xParser(tc.vector2)
        vector2, _ := parser2.Parse()
        
        calc1 := cvss.NewCalculator(vector1)
        calc2 := cvss.NewCalculator(vector2)
        
        score1, _ := calc1.Calculate()
        score2, _ := calc2.Calculate()
        
        var actual string
        if score1 > score2 {
            actual = "higher"
        } else if score1 < score2 {
            actual = "lower"
        } else {
            actual = "equal"
        }
        
        if actual == tc.expected {
            fmt.Printf("✓ 通过: 向量 1 比向量 2 %s (%.1f vs %.1f)\n", actual, score1, score2)
        } else {
            fmt.Printf("✗ 失败: 期望 %s，得到 %s (%.1f vs %.1f)\n", tc.expected, actual, score1, score2)
        }
    }
}
```

## 下一步

掌握向量比较后，您可以探索：

- [严重性级别](/zh/examples/severity) - 理解严重性分类
- [边缘情况](/zh/examples/edge-cases) - 处理复杂比较场景
- [距离计算](/zh/examples/distance) - 数学相似性分析

## 相关文档

- [向量比较 API](/zh/api/cvss/comparison) - 详细 API 参考
- [距离计算器](/zh/api/cvss/distance) - 数学比较方法
- [风险评估指南](/zh/examples/risk-assessment) - 全面的风险分析
