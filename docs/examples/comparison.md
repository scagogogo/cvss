# Vector Comparison Examples

This example demonstrates various methods for comparing CVSS vectors, including side-by-side analysis, metric-level comparison, and automated comparison tools.

## Overview

Vector comparison is essential for:

- Vulnerability prioritization
- Risk assessment validation
- Security control effectiveness measurement
- Vulnerability evolution tracking
- Compliance reporting

## Basic Vector Comparison

### Simple Side-by-Side Comparison

```go
package main

import (
    "fmt"
    "log"

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

    fmt.Println("=== Basic Vector Comparison ===")
    
    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    scores := make([]float64, len(vectors))
    severities := make([]string, len(vectors))

    // Parse all vectors and calculate scores
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

        fmt.Printf("Vector %d: %s\n", i+1, vectorStr)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Println()
    }

    // Find highest and lowest scores
    maxScore, maxIndex := findMaxScore(scores)
    minScore, minIndex := findMinScore(scores)

    fmt.Printf("Highest Risk: Vector %d (%.1f - %s)\n", maxIndex+1, maxScore, severities[maxIndex])
    fmt.Printf("Lowest Risk: Vector %d (%.1f - %s)\n", minIndex+1, minScore, severities[minIndex])
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

### Detailed Metric Comparison

```go
func compareVectorsDetailed(v1, v2 *cvss.Cvss3x) {
    fmt.Println("=== Detailed Vector Comparison ===")
    fmt.Printf("Vector 1: %s\n", v1.String())
    fmt.Printf("Vector 2: %s\n", v2.String())
    fmt.Println()

    // Compare base metrics
    fmt.Println("Base Metrics Comparison:")
    compareMetric("Attack Vector", 
        v1.Cvss3xBase.AttackVector, 
        v2.Cvss3xBase.AttackVector)
    compareMetric("Attack Complexity", 
        v1.Cvss3xBase.AttackComplexity, 
        v2.Cvss3xBase.AttackComplexity)
    compareMetric("Privileges Required", 
        v1.Cvss3xBase.PrivilegesRequired, 
        v2.Cvss3xBase.PrivilegesRequired)
    compareMetric("User Interaction", 
        v1.Cvss3xBase.UserInteraction, 
        v2.Cvss3xBase.UserInteraction)
    compareMetric("Scope", 
        v1.Cvss3xBase.Scope, 
        v2.Cvss3xBase.Scope)
    compareMetric("Confidentiality Impact",
        v1.Cvss3xBase.Confidentiality,
        v2.Cvss3xBase.Confidentiality)
    compareMetric("Integrity Impact",
        v1.Cvss3xBase.Integrity,
        v2.Cvss3xBase.Integrity)
    compareMetric("Availability Impact",
        v1.Cvss3xBase.Availability,
        v2.Cvss3xBase.Availability)

    // Compare scores
    calc1 := cvss.NewCalculator(v1)
    calc2 := cvss.NewCalculator(v2)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("\nScore Comparison:\n")
    fmt.Printf("  Vector 1: %.1f (%s)\n", score1, calc1.GetSeverityRating(score1))
    fmt.Printf("  Vector 2: %.1f (%s)\n", score2, calc2.GetSeverityRating(score2))
    fmt.Printf("  Difference: %.1f points\n", abs(score1-score2))
    
    if score1 > score2 {
        fmt.Printf("  Vector 1 is higher risk by %.1f points\n", score1-score2)
    } else if score2 > score1 {
        fmt.Printf("  Vector 2 is higher risk by %.1f points\n", score2-score1)
    } else {
        fmt.Printf("  Vectors have equal risk scores\n")
    }
}

func compareMetric(name string, m1, m2 vector.Vector) {
    if m1.GetShortValue() == m2.GetShortValue() {
        fmt.Printf("  %-25s: %s (same)\n", name, m1.GetLongValue())
    } else {
        fmt.Printf("  %-25s: %s vs %s\n", name, m1.GetLongValue(), m2.GetLongValue())
        
        score1 := m1.GetScore()
        score2 := m2.GetScore()
        if score1 > score2 {
            fmt.Printf("  %25s  Vector 1 higher (%.2f vs %.2f)\n", "", score1, score2)
        } else if score2 > score1 {
            fmt.Printf("  %25s  Vector 2 higher (%.2f vs %.2f)\n", "", score2, score1)
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

## Comparison Matrix

### Multi-Vector Comparison Matrix

```go
func createComparisonMatrix(vectors []*cvss.Cvss3x) {
    fmt.Println("=== Vector Comparison Matrix ===")
    
    // Calculate scores for all vectors
    scores := make([]float64, len(vectors))
    severities := make([]string, len(vectors))
    
    for i, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        
        scores[i] = score
        severities[i] = severity
    }

    // Print header
    fmt.Printf("%10s", "")
    for i := range vectors {
        fmt.Printf("%12s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    // Print scores
    fmt.Printf("%10s", "Score")
    for _, score := range scores {
        fmt.Printf("%12.1f", score)
    }
    fmt.Println()

    fmt.Printf("%10s", "Severity")
    for _, severity := range severities {
        fmt.Printf("%12s", severity)
    }
    fmt.Println()

    // Print comparison matrix
    fmt.Println("\nScore Differences:")
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

### Metric-Level Comparison Matrix

```go
func createMetricComparisonMatrix(vectors []*cvss.Cvss3x) {
    fmt.Println("=== Metric Comparison Matrix ===")
    
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

    // Print header
    fmt.Printf("%8s", "Metric")
    for i := range vectors {
        fmt.Printf("%8s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    // Print each metric
    for _, metric := range metrics {
        fmt.Printf("%8s", metric.name)
        for _, vector := range vectors {
            m := metric.getter(vector)
            fmt.Printf("%8c", m.GetShortValue())
        }
        fmt.Println()
    }

    // Print scores
    fmt.Printf("%8s", "Score")
    for _, vector := range vectors {
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        fmt.Printf("%8.1f", score)
    }
    fmt.Println()
}
```

## Vulnerability Evolution Tracking

### Version Comparison

```go
func trackVulnerabilityEvolution() {
    versions := []struct {
        version string
        vector  string
        changes string
    }{
        {
            "Initial Report",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Initial assessment",
        },
        {
            "After Analysis",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "Requires authentication, higher complexity",
        },
        {
            "With Workaround",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:P/RL:W/RC:C",
            "Workaround reduces impact, PoC available",
        },
        {
            "After Patch",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:F/RL:O/RC:C",
            "Official fix available, exploit functional",
        },
    }

    fmt.Println("=== Vulnerability Evolution Tracking ===")
    
    var previousScore float64
    
    for i, version := range versions {
        vector, _ := parser.ParseString(version.vector)
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("Version %d: %s\n", i+1, version.version)
        fmt.Printf("  Vector: %s\n", version.vector)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Printf("  Changes: %s\n", version.changes)
        
        if i > 0 {
            change := score - previousScore
            if change > 0 {
                fmt.Printf("  Score Change: +%.1f (increased risk)\n", change)
            } else if change < 0 {
                fmt.Printf("  Score Change: %.1f (decreased risk)\n", change)
            } else {
                fmt.Printf("  Score Change: 0.0 (no change)\n")
            }
        }
        
        previousScore = score
        fmt.Println()
    }
}
```

### Change Impact Analysis

```go
func analyzeChangeImpact(original, modified *cvss.Cvss3x) {
    fmt.Println("=== Change Impact Analysis ===")
    
    calc1 := cvss.NewCalculator(original)
    calc2 := cvss.NewCalculator(modified)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("Original: %s (%.1f)\n", original.String(), score1)
    fmt.Printf("Modified: %s (%.1f)\n", modified.String(), score2)
    fmt.Printf("Score Change: %.1f points\n", score2-score1)
    
    // Analyze which metrics changed
    changes := findMetricChanges(original, modified)
    
    if len(changes) == 0 {
        fmt.Println("No metric changes detected")
    } else {
        fmt.Printf("\nMetric Changes (%d):\n", len(changes))
        for _, change := range changes {
            fmt.Printf("  %s: %s → %s\n", change.Metric, change.From, change.To)
            
            impact := change.ScoreImpact
            if impact > 0 {
                fmt.Printf("    Impact: +%.2f (increases risk)\n", impact)
            } else if impact < 0 {
                fmt.Printf("    Impact: %.2f (decreases risk)\n", impact)
            } else {
                fmt.Printf("    Impact: 0.00 (no score change)\n")
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
    
    // Compare base metrics
    if v1.Cvss3xBase.AttackVector.GetShortValue() != v2.Cvss3xBase.AttackVector.GetShortValue() {
        changes = append(changes, MetricChange{
            Metric: "Attack Vector",
            From:   v1.Cvss3xBase.AttackVector.GetLongValue(),
            To:     v2.Cvss3xBase.AttackVector.GetLongValue(),
            ScoreImpact: v2.Cvss3xBase.AttackVector.GetScore() - v1.Cvss3xBase.AttackVector.GetScore(),
        })
    }
    
    // ... compare other metrics similarly
    
    return changes
}
```

## Risk Prioritization

### Multi-Criteria Comparison

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
        
        // Calculate additional risk factors
        ranking.ExploitabilityScore = calculateExploitabilityScore(vector)
        ranking.ImpactScore = calculateImpactScore(vector)
        ranking.RiskFactors = analyzeRiskFactors(vector)
        
        rankings = append(rankings, ranking)
    }
    
    // Sort by score (highest first)
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
    // Simplified exploitability calculation
    av := vector.Cvss3xBase.AttackVector.GetScore()
    ac := vector.Cvss3xBase.AttackComplexity.GetScore()
    pr := vector.Cvss3xBase.PrivilegesRequired.GetScore()
    ui := vector.Cvss3xBase.UserInteraction.GetScore()
    
    return 8.22 * av * ac * pr * ui
}

func calculateImpactScore(vector *cvss.Cvss3x) float64 {
    // Simplified impact calculation
    c := vector.Cvss3xBase.Confidentiality.GetScore()
    i := vector.Cvss3xBase.Integrity.GetScore()
    a := vector.Cvss3xBase.Availability.GetScore()
    
    return 6.42 * (1 - (1-c) * (1-i) * (1-a))
}

func analyzeRiskFactors(vector *cvss.Cvss3x) []string {
    var factors []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        factors = append(factors, "Network accessible")
    }
    
    if vector.Cvss3xBase.AttackComplexity.GetShortValue() == 'L' {
        factors = append(factors, "Low attack complexity")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        factors = append(factors, "No privileges required")
    }
    
    if vector.Cvss3xBase.UserInteraction.GetShortValue() == 'N' {
        factors = append(factors, "No user interaction")
    }
    
    return factors
}

func printVulnerabilityRankings(rankings []VulnerabilityRanking) {
    fmt.Println("=== Vulnerability Priority Ranking ===")
    
    for i, ranking := range rankings {
        fmt.Printf("Rank %d: Vector %d\n", i+1, ranking.Index+1)
        fmt.Printf("  Score: %.1f (%s)\n", ranking.Score, ranking.Severity)
        fmt.Printf("  Exploitability: %.1f\n", ranking.ExploitabilityScore)
        fmt.Printf("  Impact: %.1f\n", ranking.ImpactScore)
        fmt.Printf("  Vector: %s\n", ranking.Vector.String())
        
        if len(ranking.RiskFactors) > 0 {
            fmt.Printf("  Risk Factors: %s\n", strings.Join(ranking.RiskFactors, ", "))
        }
        fmt.Println()
    }
}
```

### Comparative Risk Assessment

```go
func compareRiskProfiles(vectors []*cvss.Cvss3x) {
    fmt.Println("=== Comparative Risk Assessment ===")
    
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
            CIAImpact:    fmt.Sprintf("%s/%s/%s",
                vector.Cvss3xBase.Confidentiality.GetShortValue(),
                vector.Cvss3xBase.Integrity.GetShortValue(),
                vector.Cvss3xBase.Availability.GetShortValue()),
        }
    }
    
    // Print comparison table
    fmt.Printf("%-8s %-8s %-12s %-12s %-12s %-12s %-12s %-8s\n",
        "Vector", "Score", "Severity", "Attack Vec", "Complexity", "Privileges", "Interaction", "C/I/A")
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

## Automated Comparison Tools

### Batch Comparison

```go
func batchCompareVectors(vectors []string) {
    fmt.Println("=== Batch Vector Comparison ===")
    
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
    
    // Sort by score
    sort.Slice(results, func(i, j int) bool {
        return results[i].Score > results[j].Score
    })
    
    // Print results
    for i, result := range results {
        fmt.Printf("Rank %d: ", i+1)
        if result.Error != nil {
            fmt.Printf("ERROR - %s: %v\n", result.Vector, result.Error)
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

## Testing and Validation

### Comparison Accuracy Testing

```go
func testComparisonAccuracy() {
    testCases := []struct {
        name     string
        vector1  string
        vector2  string
        expected string // "higher", "lower", "equal"
    }{
        {
            "Network vs Local",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "higher",
        },
        {
            "High vs Low Impact",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "higher",
        },
        {
            "Same Vectors",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "equal",
        },
    }

    fmt.Println("=== Comparison Accuracy Testing ===")

    for _, tc := range testCases {
        fmt.Printf("\nTest: %s\n", tc.name)
        
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
            fmt.Printf("✓ PASS: Vector 1 is %s than Vector 2 (%.1f vs %.1f)\n", actual, score1, score2)
        } else {
            fmt.Printf("✗ FAIL: Expected %s, got %s (%.1f vs %.1f)\n", tc.expected, actual, score1, score2)
        }
    }
}
```

## Next Steps

After mastering vector comparison, you can explore:

- [Severity Levels](/examples/severity) - Understanding severity classifications
- [Edge Cases](/examples/edge-cases) - Handling complex comparison scenarios
- [Distance Calculation](/examples/distance) - Mathematical similarity analysis

## Related Documentation

- [Vector Comparison API](/api/cvss/comparison) - Detailed API reference
- [Distance Calculator](/api/cvss/distance) - Mathematical comparison methods
- [Risk Assessment Guide](/examples/risk-assessment) - Comprehensive risk analysis
