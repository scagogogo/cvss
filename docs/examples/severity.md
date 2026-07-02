# Severity Levels Examples

This example demonstrates how to work with CVSS severity ratings, understand severity thresholds, and implement custom severity classification systems.

## Overview

CVSS severity ratings provide a qualitative representation of vulnerability risk:

- **None**: 0.0
- **Low**: 0.1 - 3.9
- **Medium**: 4.0 - 6.9
- **High**: 7.0 - 8.9
- **Critical**: 9.0 - 10.0

## Basic Severity Classification

### Standard CVSS Severity Ratings

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
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",     // None
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // Low
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // Medium
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // High
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // Critical
    }

    fmt.Println("=== CVSS Severity Classification ===")
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            log.Fatal(err)
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("Example %d: %s\n", i+1, vectorStr)
        fmt.Printf("  Score: %.1f\n", score)
        fmt.Printf("  Severity: %s\n", severity)
        fmt.Printf("  Description: %s\n", getSeverityDescription(severity))
        fmt.Println()
    }
}

func getSeverityDescription(severity string) string {
    descriptions := map[string]string{
        "None":     "No impact to the organization",
        "Low":      "Minimal impact to the organization",
        "Medium":   "Moderate impact to the organization",
        "High":     "Significant impact to the organization",
        "Critical": "Severe impact to the organization",
    }
    return descriptions[severity]
}
```

### Severity Threshold Analysis

```go
func analyzeSeverityThresholds() {
    fmt.Println("=== Severity Threshold Analysis ===")
    
    // Test scores around threshold boundaries
    testScores := []float64{0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0}
    
    fmt.Printf("%-8s %-10s %-15s\n", "Score", "Severity", "Threshold")
    fmt.Println(strings.Repeat("-", 35))
    
    for _, score := range testScores {
        severity := getSeverityFromScore(score)
        threshold := getSeverityThreshold(severity)
        
        fmt.Printf("%-8.1f %-10s %-15s\n", score, severity, threshold)
    }
}

func getSeverityFromScore(score float64) string {
    if score == 0.0 {
        return "None"
    } else if score >= 0.1 && score <= 3.9 {
        return "Low"
    } else if score >= 4.0 && score <= 6.9 {
        return "Medium"
    } else if score >= 7.0 && score <= 8.9 {
        return "High"
    } else if score >= 9.0 && score <= 10.0 {
        return "Critical"
    }
    return "Unknown"
}

func getSeverityThreshold(severity string) string {
    thresholds := map[string]string{
        "None":     "0.0",
        "Low":      "0.1 - 3.9",
        "Medium":   "4.0 - 6.9",
        "High":     "7.0 - 8.9",
        "Critical": "9.0 - 10.0",
    }
    return thresholds[severity]
}
```

## Custom Severity Systems

### Organizational Severity Mapping

```go
func demonstrateCustomSeverity() {
    vectors := []string{
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // CVSS: Low
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // CVSS: Medium
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // CVSS: High
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // CVSS: Critical
    }

    fmt.Println("=== Custom Organizational Severity Mapping ===")
    
    for i, vectorStr := range vectors {
        vector, _ := parser.ParseString(vectorStr)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        
        standardSeverity := calculator.GetSeverityRating(score)
        customSeverity := getCustomSeverity(score, vector)
        
        fmt.Printf("Vector %d: %s\n", i+1, vectorStr)
        fmt.Printf("  Score: %.1f\n", score)
        fmt.Printf("  Standard Severity: %s\n", standardSeverity)
        fmt.Printf("  Custom Severity: %s\n", customSeverity)
        fmt.Printf("  Rationale: %s\n", getCustomSeverityRationale(score, vector))
        fmt.Println()
    }
}

func getCustomSeverity(score float64, vector *cvss.Cvss3x) string {
    // Custom severity logic based on organizational needs
    
    // Elevate network-accessible vulnerabilities
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' && score >= 4.0 {
        if score >= 7.0 {
            return "CRITICAL+"
        } else if score >= 4.0 {
            return "HIGH+"
        }
    }
    
    // Reduce severity for local-only vulnerabilities requiring high privileges
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'L' && 
       vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'H' {
        if score >= 7.0 {
            return "MEDIUM+"
        } else if score >= 4.0 {
            return "LOW+"
        }
    }
    
    // Default to standard severity
    return getSeverityFromScore(score)
}

func getCustomSeverityRationale(score float64, vector *cvss.Cvss3x) string {
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' && score >= 4.0 {
        return "Elevated due to network accessibility"
    }
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'L' && 
       vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'H' {
        return "Reduced due to local access and high privilege requirements"
    }
    
    return "Standard CVSS severity mapping"
}
```

### Industry-Specific Severity

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
            "Financial Services",
            "CRITICAL",
            "High confidentiality impact affects customer financial data",
        },
        {
            "Healthcare",
            "HIGH+",
            "Patient data confidentiality is paramount for HIPAA compliance",
        },
        {
            "E-commerce",
            "HIGH",
            "Customer data exposure could impact business reputation",
        },
        {
            "Internal IT",
            "MEDIUM+",
            "Limited business impact but requires prompt attention",
        },
        {
            "Public Website",
            "MEDIUM",
            "Standard severity as no sensitive data exposed",
        },
    }

    fmt.Println("=== Industry-Specific Severity Classification ===")
    fmt.Printf("Vector: %s\n", vector)
    fmt.Printf("Standard Score: %.1f (%s)\n\n", score, standardSeverity)
    
    for _, industry := range industries {
        fmt.Printf("Industry: %s\n", industry.name)
        fmt.Printf("  Severity: %s\n", industry.severity)
        fmt.Printf("  Rationale: %s\n", industry.rationale)
        fmt.Println()
    }
}
```

## Severity-Based Processing

### Severity Filtering

```go
func filterBySeverity(vectors []string, minSeverity string) []VulnerabilityInfo {
    severityOrder := map[string]int{
        "None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
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
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // Low
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // Medium
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     // High
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // Critical
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L",     // Low
    }
    
    severityLevels := []string{"Medium", "High", "Critical"}
    
    fmt.Println("=== Severity-Based Filtering ===")
    
    for _, level := range severityLevels {
        filtered := filterBySeverity(vectors, level)
        
        fmt.Printf("\nFiltering for %s and above:\n", level)
        fmt.Printf("Found %d vulnerabilities:\n", len(filtered))
        
        for _, vuln := range filtered {
            fmt.Printf("  ID %d: %.1f (%s)\n", vuln.ID, vuln.Score, vuln.Severity)
        }
    }
}
```

### Severity-Based Prioritization

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
    
    // Sort by priority (higher priority first)
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
        "None": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5,
    }
    
    priority := basePriority[severity]
    
    // Boost priority for network-accessible vulnerabilities
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        priority += 1
    }
    
    // Boost priority for no authentication required
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        priority += 1
    }
    
    return priority
}

func getSLA(severity string) string {
    slas := map[string]string{
        "None":     "30 days",
        "Low":      "30 days",
        "Medium":   "14 days",
        "High":     "7 days",
        "Critical": "24 hours",
    }
    return slas[severity]
}

func demonstrateSeverityPrioritization() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // Critical, Network, No Auth
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",     // High, Local, High Auth
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",     // Medium, Network, Low Auth
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",     // Low, Local, High Auth
    }
    
    priorities := prioritizeBySeverity(vectors)
    
    fmt.Println("=== Severity-Based Prioritization ===")
    fmt.Printf("%-4s %-8s %-10s %-8s %-10s %-12s\n", 
        "Rank", "ID", "Severity", "Score", "Priority", "SLA")
    fmt.Println(strings.Repeat("-", 60))
    
    for i, item := range priorities {
        fmt.Printf("%-4d %-8d %-10s %-8.1f %-10d %-12s\n",
            i+1, item.ID, item.Severity, item.Score, item.Priority, item.SLA)
    }
}
```

## Severity Reporting

### Severity Distribution Analysis

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
    
    fmt.Println("=== Severity Distribution Analysis ===")
    fmt.Printf("Total Vulnerabilities: %d\n", validVectors)
    fmt.Printf("Average Score: %.1f\n\n", totalScore/float64(validVectors))
    
    severityOrder := []string{"Critical", "High", "Medium", "Low", "None"}
    
    fmt.Printf("%-10s %-8s %-12s %-10s\n", "Severity", "Count", "Percentage", "Bar")
    fmt.Println(strings.Repeat("-", 45))
    
    for _, severity := range severityOrder {
        count := distribution[severity]
        percentage := float64(count) / float64(validVectors) * 100
        bar := strings.Repeat("█", int(percentage/2)) // Scale bar to fit
        
        fmt.Printf("%-10s %-8d %-12.1f%% %s\n", severity, count, percentage, bar)
    }
}
```

### Severity Trend Analysis

```go
func analyzeSeverityTrends(historicalData []HistoricalSnapshot) {
    fmt.Println("=== Severity Trend Analysis ===")
    
    fmt.Printf("%-12s %-8s %-8s %-8s %-8s %-8s\n", 
        "Date", "Critical", "High", "Medium", "Low", "Total")
    fmt.Println(strings.Repeat("-", 60))
    
    for _, snapshot := range historicalData {
        distribution := calculateSeverityDistribution(snapshot.Vectors)
        total := 0
        for _, count := range distribution {
            total += count
        }
        
        fmt.Printf("%-12s %-8d %-8d %-8d %-8d %-8d\n",
            snapshot.Date,
            distribution["Critical"],
            distribution["High"],
            distribution["Medium"],
            distribution["Low"],
            total)
    }
    
    // Calculate trends
    if len(historicalData) >= 2 {
        fmt.Println("\nTrend Analysis:")
        latest := calculateSeverityDistribution(historicalData[len(historicalData)-1].Vectors)
        previous := calculateSeverityDistribution(historicalData[len(historicalData)-2].Vectors)
        
        for _, severity := range []string{"Critical", "High", "Medium", "Low"} {
            change := latest[severity] - previous[severity]
            if change > 0 {
                fmt.Printf("  %s: +%d (increased)\n", severity, change)
            } else if change < 0 {
                fmt.Printf("  %s: %d (decreased)\n", severity, change)
            } else {
                fmt.Printf("  %s: no change\n", severity)
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

## Severity Validation

### Severity Consistency Checking

```go
func validateSeverityConsistency(vectors []string) []SeverityIssue {
    var issues []SeverityIssue
    
    for i, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       "Parse error: " + err.Error(),
                Type:        "PARSE_ERROR",
            })
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        // Check for potential inconsistencies
        if severity == "Critical" && score < 9.5 {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       fmt.Sprintf("Low critical score: %.1f", score),
                Type:        "LOW_CRITICAL",
            })
        }
        
        if severity == "Low" && vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       "Network-accessible vulnerability rated as Low",
                Type:        "NETWORK_LOW",
            })
        }
        
        // Check for score-severity misalignment
        expectedSeverity := getSeverityFromScore(score)
        if expectedSeverity != severity {
            issues = append(issues, SeverityIssue{
                VectorIndex: i,
                Vector:      vectorStr,
                Issue:       fmt.Sprintf("Severity mismatch: expected %s, got %s", expectedSeverity, severity),
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
        fmt.Println("✓ No severity issues found")
        return
    }
    
    fmt.Printf("Found %d severity issues:\n\n", len(issues))
    
    for _, issue := range issues {
        fmt.Printf("Issue: %s\n", issue.Issue)
        fmt.Printf("  Type: %s\n", issue.Type)
        fmt.Printf("  Vector %d: %s\n", issue.VectorIndex+1, issue.Vector)
        fmt.Println()
    }
}
```

## Testing and Validation

### Severity Classification Testing

```go
func testSeverityClassification() {
    testCases := []struct {
        score    float64
        expected string
    }{
        {0.0, "None"},
        {0.1, "Low"},
        {3.9, "Low"},
        {4.0, "Medium"},
        {6.9, "Medium"},
        {7.0, "High"},
        {8.9, "High"},
        {9.0, "Critical"},
        {10.0, "Critical"},
    }

    fmt.Println("=== Severity Classification Testing ===")

    for _, tc := range testCases {
        actual := getSeverityFromScore(tc.score)
        
        if actual == tc.expected {
            fmt.Printf("✓ Score %.1f -> %s\n", tc.score, actual)
        } else {
            fmt.Printf("✗ Score %.1f -> %s (expected %s)\n", tc.score, actual, tc.expected)
        }
    }
}
```

## Next Steps

After mastering severity levels, you can explore:

- [Edge Cases](/examples/edge-cases) - Handling complex severity scenarios
- [Vector Comparison](/examples/comparison) - Comparing severity across vectors
- [Risk Assessment](/examples/risk-assessment) - Comprehensive risk analysis

## Related Documentation

- [Severity API Reference](/api/cvss/calculator) - Detailed API documentation
- [Calculator](/api/cvss/calculator) - Score calculation methods
- [Risk Management Guide](/examples/risk-assessment) - Enterprise risk management
