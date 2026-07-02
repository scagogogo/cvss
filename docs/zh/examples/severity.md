# 严重性级别示例

本示例演示如何使用 CVSS 严重性评级，理解严重性阈值，并实施自定义严重性分类系统。

## 概述

CVSS 严重性评级提供漏洞风险的定性表示：

- **无**: 0.0
- **低**: 0.1 - 3.9
- **中等**: 4.0 - 6.9
- **高**: 7.0 - 8.9
- **严重**: 9.0 - 10.0

## 基本严重性分类

### 标准 CVSS 严重性评级

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectors := []string{
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",     // 无
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // 低
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // 中等
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // 高
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // 严重
    }

    fmt.Println("=== CVSS 严重性分类 ===")
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            log.Fatal(err)
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("示例 %d: %s\n", i+1, vectorStr)
        fmt.Printf("  分数: %.1f\n", score)
        fmt.Printf("  严重性: %s\n", severity)
        fmt.Printf("  描述: %s\n", getSeverityDescription(severity))
        fmt.Println()
    }
}

func getSeverityDescription(severity string) string {
    descriptions := map[string]string{
        "None":     "对组织无影响",
        "Low":      "对组织影响最小",
        "Medium":   "对组织影响中等",
        "High":     "对组织影响重大",
        "Critical": "对组织影响严重",
    }
    return descriptions[severity]
}
```

### 严重性阈值分析

```go
func analyzeSeverityThresholds() {
    fmt.Println("=== 严重性阈值分析 ===")
    
    // 测试阈值边界附近的分数
    testScores := []float64{0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0}
    
    fmt.Printf("%-8s %-10s %-15s\n", "分数", "严重性", "阈值")
    fmt.Println(strings.Repeat("-", 35))
    
    for _, score := range testScores {
        severity := getSeverityFromScore(score)
        threshold := getSeverityThreshold(severity)
        
        fmt.Printf("%-8.1f %-10s %-15s\n", score, severity, threshold)
    }
}

func getSeverityFromScore(score float64) string {
    if score == 0.0 {
        return "无"
    } else if score >= 0.1 && score <= 3.9 {
        return "低"
    } else if score >= 4.0 && score <= 6.9 {
        return "中等"
    } else if score >= 7.0 && score <= 8.9 {
        return "高"
    } else if score >= 9.0 && score <= 10.0 {
        return "严重"
    }
    return "未知"
}

func getSeverityThreshold(severity string) string {
    thresholds := map[string]string{
        "无":   "0.0",
        "低":   "0.1 - 3.9",
        "中等": "4.0 - 6.9",
        "高":   "7.0 - 8.9",
        "严重": "9.0 - 10.0",
    }
    return thresholds[severity]
}
```

## 自定义严重性系统

### 组织严重性映射

```go
func demonstrateCustomSeverity() {
    vectors := []string{
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // CVSS: 低
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // CVSS: 中等
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // CVSS: 高
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // CVSS: 严重
    }

    fmt.Println("=== 自定义组织严重性映射 ===")
    
    for i, vectorStr := range vectors {
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        
        standardSeverity := calculator.GetSeverityRating(score)
        customSeverity := getCustomSeverity(score, vector)
        
        fmt.Printf("向量 %d: %s\n", i+1, vectorStr)
        fmt.Printf("  分数: %.1f\n", score)
        fmt.Printf("  标准严重性: %s\n", standardSeverity)
        fmt.Printf("  自定义严重性: %s\n", customSeverity)
        fmt.Printf("  理由: %s\n", getCustomSeverityRationale(score, vector))
        fmt.Println()
    }
}

func getCustomSeverity(score float64, vector *cvss.Cvss3x) string {
    // 基于组织需求的自定义严重性逻辑
    
    // 提升网络可访问漏洞的严重性
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' && score >= 4.0 {
        if score >= 7.0 {
            return "严重+"
        } else if score >= 4.0 {
            return "高+"
        }
    }
    
    // 降低需要高权限的本地漏洞严重性
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'L' && 
       vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'H' {
        if score >= 7.0 {
            return "中等+"
        } else if score >= 4.0 {
            return "低+"
        }
    }
    
    // 默认使用标准严重性
    return getSeverityFromScore(score)
}

func getCustomSeverityRationale(score float64, vector *cvss.Cvss3x) string {
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' && score >= 4.0 {
        return "由于网络可访问性而提升"
    }
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'L' && 
       vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'H' {
        return "由于本地访问和高权限要求而降低"
    }
    
    return "标准 CVSS 严重性映射"
}
```

### 行业特定严重性

```go
func demonstrateIndustrySeverity() {
    vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
    
    parsedVector, _ := parser.ParseString(vector)
    
    calculator := cvss.NewCalculator(parsedVector)
    score, _ := calculator.Calculate()
    standardSeverity := calculator.GetSeverityRating(score)
    
    industries := []struct {
        name     string
        severity string
        rationale string
    }{
        {
            "金融服务",
            "严重",
            "高机密性影响影响客户金融数据",
        },
        {
            "医疗保健",
            "高+",
            "患者数据机密性对 HIPAA 合规至关重要",
        },
        {
            "电子商务",
            "高",
            "客户数据暴露可能影响业务声誉",
        },
        {
            "内部IT",
            "中等+",
            "业务影响有限但需要及时关注",
        },
        {
            "公共网站",
            "中等",
            "标准严重性，因为没有敏感数据暴露",
        },
    }

    fmt.Println("=== 行业特定严重性分类 ===")
    fmt.Printf("向量: %s\n", vector)
    fmt.Printf("标准分数: %.1f (%s)\n\n", score, standardSeverity)
    
    for _, industry := range industries {
        fmt.Printf("行业: %s\n", industry.name)
        fmt.Printf("  严重性: %s\n", industry.severity)
        fmt.Printf("  理由: %s\n", industry.rationale)
        fmt.Println()
    }
}
```

## 基于严重性的处理

### 严重性过滤

```go
func filterBySeverity(vectors []string, minSeverity string) []VulnerabilityInfo {
    severityOrder := map[string]int{
        "无": 0, "低": 1, "中等": 2, "高": 3, "严重": 4,
    }
    
    minLevel := severityOrder[minSeverity]
    var filtered []VulnerabilityInfo
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        if severityOrder[severity] >= minLevel {
            filtered = append(filtered, VulnerabilityInfo{
                ID:       i + 1,
                Vector:   vectorStr,
                Score:    score,
                Severity: severity,
            })
        }
    }
    
    return filtered
}

type VulnerabilityInfo struct {
    ID       int
    Vector   string
    Score    float64
    Severity string
}

func demonstrateSeverityFiltering() {
    vectors := []string{
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // 低
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // 中等
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // 高
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // 严重
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L",     // 低
    }
    
    severityLevels := []string{"中等", "高", "严重"}
    
    fmt.Println("=== 基于严重性的过滤 ===")
    
    for _, level := range severityLevels {
        filtered := filterBySeverity(vectors, level)
        
        fmt.Printf("\n过滤 %s 及以上:\n", level)
        fmt.Printf("找到 %d 个漏洞:\n", len(filtered))
        
        for _, vuln := range filtered {
            fmt.Printf("  ID %d: %.1f (%s)\n", vuln.ID, vuln.Score, vuln.Severity)
        }
    }
}
```

### 基于严重性的优先级排序

```go
func prioritizeBySeverity(vectors []string) []PriorityItem {
    var items []PriorityItem
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        items = append(items, PriorityItem{
            ID:       i + 1,
            Vector:   vectorStr,
            Score:    score,
            Severity: severity,
            Priority: calculatePriority(severity, vector),
            SLA:      getSLA(severity),
        })
    }
    
    // 按优先级排序（高优先级在前）
    sort.Slice(items, func(i, j int) bool {
        return items[i].Priority > items[j].Priority
    })
    
    return items
}

type PriorityItem struct {
    ID       int
    Vector   string
    Score    float64
    Severity string
    Priority int
    SLA      string
}

func calculatePriority(severity string, vector *cvss.Cvss3x) int {
    basePriority := map[string]int{
        "无": 1, "低": 2, "中等": 3, "高": 4, "严重": 5,
    }
    
    priority := basePriority[severity]
    
    // 为网络可访问漏洞提升优先级
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        priority += 1
    }
    
    // 为无需身份验证的漏洞提升优先级
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        priority += 1
    }
    
    return priority
}

func getSLA(severity string) string {
    slas := map[string]string{
        "无":   "30天",
        "低":   "30天",
        "中等": "14天",
        "高":   "7天",
        "严重": "24小时",
    }
    return slas[severity]
}

func demonstrateSeverityPrioritization() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // 严重，网络，无认证
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",     // 高，本地，高认证
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // 中等，网络，低认证
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // 低，本地，高认证
    }
    
    priorities := prioritizeBySeverity(vectors)
    
    fmt.Println("=== 基于严重性的优先级排序 ===")
    fmt.Printf("%-4s %-8s %-10s %-8s %-10s %-12s\n", 
        "排名", "ID", "严重性", "分数", "优先级", "SLA")
    fmt.Println(strings.Repeat("-", 60))
    
    for i, item := range priorities {
        fmt.Printf("%-4d %-8d %-10s %-8.1f %-10d %-12s\n",
            i+1, item.ID, item.Severity, item.Score, item.Priority, item.SLA)
    }
}
```

## 严重性报告

### 严重性分布分析

```go
func analyzeSeverityDistribution(vectors []string) {
    distribution := make(map[string]int)
    var totalScore float64
    validVectors := 0
    
    for _, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        distribution[severity]++
        totalScore += score
        validVectors++
    }
    
    fmt.Println("=== 严重性分布分析 ===")
    fmt.Printf("总漏洞数: %d\n", validVectors)
    fmt.Printf("平均分数: %.1f\n\n", totalScore/float64(validVectors))
    
    severityOrder := []string{"严重", "高", "中等", "低", "无"}
    
    fmt.Printf("%-10s %-8s %-12s %-10s\n", "严重性", "数量", "百分比", "条形图")
    fmt.Println(strings.Repeat("-", 45))
    
    for _, severity := range severityOrder {
        count := distribution[severity]
        percentage := float64(count) / float64(validVectors) * 100
        bar := strings.Repeat("█", int(percentage/2)) // 缩放条形图以适应
        
        fmt.Printf("%-10s %-8d %-12.1f%% %s\n", severity, count, percentage, bar)
    }
}
```

### 严重性趋势分析

```go
func analyzeSeverityTrends(historicalData []HistoricalSnapshot) {
    fmt.Println("=== 严重性趋势分析 ===")
    
    fmt.Printf("%-12s %-8s %-8s %-8s %-8s %-8s\n", 
        "日期", "严重", "高", "中等", "低", "总计")
    fmt.Println(strings.Repeat("-", 60))
    
    for _, snapshot := range historicalData {
        distribution := calculateSeverityDistribution(snapshot.Vectors)
        total := 0
        for _, count := range distribution {
            total += count
        }
        
        fmt.Printf("%-12s %-8d %-8d %-8d %-8d %-8d\n",
            snapshot.Date,
            distribution["严重"],
            distribution["高"],
            distribution["中等"],
            distribution["低"],
            total)
    }
    
    // 计算趋势
    if len(historicalData) >= 2 {
        fmt.Println("\n趋势分析:")
        latest := calculateSeverityDistribution(historicalData[len(historicalData)-1].Vectors)
        previous := calculateSeverityDistribution(historicalData[len(historicalData)-2].Vectors)
        
        for _, severity := range []string{"严重", "高", "中等", "低"} {
            change := latest[severity] - previous[severity]
            if change > 0 {
                fmt.Printf("  %s: +%d (增加)\n", severity, change)
            } else if change < 0 {
                fmt.Printf("  %s: %d (减少)\n", severity, change)
            } else {
                fmt.Printf("  %s: 无变化\n", severity)
            }
        }
    }
}

type HistoricalSnapshot struct {
    Date    string
    Vectors []string
}

func calculateSeverityDistribution(vectors []string) map[string]int {
    distribution := make(map[string]int)
    
    for _, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        distribution[severity]++
    }
    
    return distribution
}
```

## 严重性验证

### 严重性一致性检查

```go
func validateSeverityConsistency(vectors []string) []SeverityIssue {
    var issues []SeverityIssue
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       "解析错误: " + err.Error(),
                Type:        "PARSE_ERROR",
            })
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        // 检查潜在的不一致性
        if severity == "严重" && score < 9.5 {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       fmt.Sprintf("低严重分数: %.1f", score),
                Type:        "LOW_CRITICAL",
            })
        }
        
        if severity == "低" && vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       "网络可访问漏洞被评为低严重性",
                Type:        "NETWORK_LOW",
            })
        }
        
        // 检查分数-严重性不匹配
        expectedSeverity := getSeverityFromScore(score)
        if expectedSeverity != severity {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       fmt.Sprintf("严重性不匹配: 期望 %s，得到 %s", expectedSeverity, severity),
                Type:        "SEVERITY_MISMATCH",
            })
        }
    }
    
    return issues
}

type SeverityIssue struct {
    VectorIndex int
    Vector      string
    Issue       string
    Type        string
}

func printSeverityIssues(issues []SeverityIssue) {
    if len(issues) == 0 {
        fmt.Println("✓ 未发现严重性问题")
        return
    }
    
    fmt.Printf("发现 %d 个严重性问题:\n\n", len(issues))
    
    for _, issue := range issues {
        fmt.Printf("问题: %s\n", issue.Issue)
        fmt.Printf("  类型: %s\n", issue.Type)
        fmt.Printf("  向量 %d: %s\n", issue.VectorIndex+1, issue.Vector)
        fmt.Println()
    }
}
```

## 测试和验证

### 严重性分类测试

```go
func testSeverityClassification() {
    testCases := []struct {
        score    float64
        expected string
    }{
        {0.0, "无"},
        {0.1, "低"},
        {3.9, "低"},
        {4.0, "中等"},
        {6.9, "中等"},
        {7.0, "高"},
        {8.9, "高"},
        {9.0, "严重"},
        {10.0, "严重"},
    }

    fmt.Println("=== 严重性分类测试 ===")

    for _, tc := range testCases {
        actual := getSeverityFromScore(tc.score)
        
        if actual == tc.expected {
            fmt.Printf("✓ 分数 %.1f -> %s\n", tc.score, actual)
        } else {
            fmt.Printf("✗ 分数 %.1f -> %s (期望 %s)\n", tc.score, actual, tc.expected)
        }
    }
}
```

## 下一步

掌握严重性级别后，您可以探索：

- [边缘情况](/zh/examples/edge-cases) - 处理复杂严重性场景
- [向量比较](/zh/examples/comparison) - 比较不同向量的严重性
- [风险评估](/zh/examples/risk-assessment) - 全面的风险分析

## 相关文档

- [严重性 API 参考](/zh/api/cvss/calculator) - 详细 API 文档
- [计算器](/zh/api/cvss/calculator) - 分数计算方法
- [风险管理指南](/zh/examples/risk-assessment) - 企业风险管理
