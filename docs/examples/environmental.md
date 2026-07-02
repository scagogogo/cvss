# Environmental Metrics Examples

This example demonstrates how to work with CVSS environmental metrics, which allow analysts to customize CVSS scores according to the importance of affected IT assets and the effectiveness of security controls in their specific environment.

## Overview

Environmental metrics consist of two categories:

**Environmental Requirements:**
- **Confidentiality Requirement (CR)** - Importance of confidentiality to the organization
- **Integrity Requirement (IR)** - Importance of integrity to the organization  
- **Availability Requirement (AR)** - Importance of availability to the organization

**Modified Base Metrics:**
- All base metrics can be modified to reflect environmental factors
- Prefixed with "M" (e.g., MAV, MAC, MPR, etc.)

## Basic Environmental Metrics

### Understanding Environmental Impact

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Base vector
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // Environmental vector with requirements
    envVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
    
    // Environmental vector with modified base metrics
    modifiedVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"

    fmt.Println("=== Environmental Metrics Impact ===")
    
    // Calculate base score
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, err := baseParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    // Calculate environmental score with requirements only
    envParser := parser.NewCvss3xParser(envVector)
    envParsed, err := envParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    envCalc := cvss.NewCalculator(envParsed)
    envScore, _ := envCalc.Calculate()

    // Calculate environmental score with modified metrics
    modParser := parser.NewCvss3xParser(modifiedVector)
    modParsed, err := modParser.Parse()
    if err != nil {
        log.Fatal(err)
    }

    modCalc := cvss.NewCalculator(modParsed)
    modScore, _ := modCalc.Calculate()

    fmt.Printf("Base Vector: %s\n", baseVector)
    fmt.Printf("Base Score: %.1f (%s)\n", baseScore, baseCalc.GetSeverityRating(baseScore))
    
    fmt.Printf("\nEnvironmental (Requirements): %s\n", envVector)
    fmt.Printf("Environmental Score: %.1f (%s)\n", envScore, envCalc.GetSeverityRating(envScore))
    fmt.Printf("Score Change: %+.1f points\n", envScore-baseScore)
    
    fmt.Printf("\nEnvironmental (Modified): %s\n", modifiedVector)
    fmt.Printf("Environmental Score: %.1f (%s)\n", modScore, modCalc.GetSeverityRating(modScore))
    fmt.Printf("Score Change: %+.1f points\n", modScore-baseScore)
}
```

### Environmental Metrics Breakdown

```go
func analyzeEnvironmentalMetrics(vector *cvss.Cvss3x) {
    if !vector.HasEnvironmental() {
        fmt.Println("No environmental metrics present")
        return
    }

    fmt.Println("=== Environmental Metrics Analysis ===")
    
    env := vector.Cvss3xEnvironmental
    
    // Requirements
    fmt.Println("Requirements:")
    if env.ConfidentialityRequirement != nil {
        fmt.Printf("  Confidentiality Requirement: %s (%c) - %.2f\n",
            env.ConfidentialityRequirement.GetLongValue(),
            env.ConfidentialityRequirement.GetShortValue(),
            env.ConfidentialityRequirement.GetScore())
    }
    
    if env.IntegrityRequirement != nil {
        fmt.Printf("  Integrity Requirement: %s (%c) - %.2f\n",
            env.IntegrityRequirement.GetLongValue(),
            env.IntegrityRequirement.GetShortValue(),
            env.IntegrityRequirement.GetScore())
    }
    
    if env.AvailabilityRequirement != nil {
        fmt.Printf("  Availability Requirement: %s (%c) - %.2f\n",
            env.AvailabilityRequirement.GetLongValue(),
            env.AvailabilityRequirement.GetShortValue(),
            env.AvailabilityRequirement.GetScore())
    }

    // Modified Base Metrics
    fmt.Println("\nModified Base Metrics:")
    if env.ModifiedAttackVector != nil {
        fmt.Printf("  Modified Attack Vector: %s (%c)\n",
            env.ModifiedAttackVector.GetLongValue(),
            env.ModifiedAttackVector.GetShortValue())
    }
    
    if env.ModifiedAttackComplexity != nil {
        fmt.Printf("  Modified Attack Complexity: %s (%c)\n",
            env.ModifiedAttackComplexity.GetLongValue(),
            env.ModifiedAttackComplexity.GetShortValue())
    }
    
    // ... other modified metrics
}
```

## Environmental Requirements

### Requirement Levels Impact

```go
func demonstrateRequirementLevels() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    requirements := []struct {
        name   string
        suffix string
        desc   string
    }{
        {"Low Requirements", "/CR:L/IR:L/AR:L", "Low importance environment"},
        {"Medium Requirements", "/CR:M/IR:M/AR:M", "Medium importance environment"},
        {"High Requirements", "/CR:H/IR:H/AR:H", "High importance environment"},
        {"Mixed Requirements", "/CR:H/IR:M/AR:L", "Mixed importance levels"},
    }

    fmt.Println("=== Environmental Requirements Impact ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    // Calculate base score
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("Base Score: %.1f\n\n", baseScore)

    for _, req := range requirements {
        vectorStr := baseVector + req.suffix
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        change := score - baseScore

        fmt.Printf("%-20s: %.1f (%s) [%+.1f]\n", req.name, score, severity, change)
        fmt.Printf("  %s\n", req.desc)
        fmt.Printf("  Vector: %s\n", vectorStr)
        fmt.Println()
    }
}
```

### Organizational Context Examples

```go
func demonstrateOrganizationalContexts() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    contexts := []struct {
        organization string
        requirements string
        rationale    string
    }{
        {
            "Financial Institution",
            "/CR:H/IR:H/AR:H",
            "All aspects critical for regulatory compliance and customer trust",
        },
        {
            "E-commerce Platform",
            "/CR:H/IR:H/AR:H",
            "Customer data protection and transaction integrity essential",
        },
        {
            "Internal Development",
            "/CR:M/IR:M/AR:L",
            "Development environment with moderate sensitivity",
        },
        {
            "Public Website",
            "/CR:L/IR:M/AR:H",
            "Public information, but availability is crucial for business",
        },
        {
            "Research Environment",
            "/CR:H/IR:M/AR:L",
            "Sensitive research data, but availability less critical",
        },
    }

    fmt.Println("=== Organizational Context Examples ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    for _, context := range contexts {
        vectorStr := baseVector + context.requirements
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("Organization: %s\n", context.organization)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Printf("  Requirements: %s\n", context.requirements)
        fmt.Printf("  Rationale: %s\n", context.rationale)
        fmt.Println()
    }
}
```

## Modified Base Metrics

### Security Controls Impact

```go
func demonstrateSecurityControls() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    controls := []struct {
        name     string
        modified string
        desc     string
    }{
        {
            "Network Segmentation",
            "/MAV:L",
            "Network controls limit attack vector to local",
        },
        {
            "Authentication Required",
            "/MPR:H",
            "Strong authentication controls in place",
        },
        {
            "User Training",
            "/MUI:R",
            "User awareness training requires interaction",
        },
        {
            "Data Encryption",
            "/MC:L",
            "Encryption reduces confidentiality impact",
        },
        {
            "Backup Systems",
            "/MA:L",
            "Redundant systems reduce availability impact",
        },
        {
            "Combined Controls",
            "/MAV:L/MPR:H/MUI:R/MC:L/MI:L/MA:L",
            "Multiple security controls implemented",
        },
    }

    fmt.Println("=== Security Controls Impact ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    // Calculate base score
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("Base Score: %.1f\n\n", baseScore)

    for _, control := range controls {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + control.modified
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        reduction := baseScore - score

        fmt.Printf("Control: %s\n", control.name)
        fmt.Printf("  Score: %.1f (%s) [%.1f reduction]\n", score, severity, reduction)
        fmt.Printf("  Modified: %s\n", control.modified)
        fmt.Printf("  Description: %s\n", control.desc)
        fmt.Println()
    }
}
```

### Defense in Depth Analysis

```go
func analyzeDefenseInDepth() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    layers := []struct {
        layer    string
        controls string
        desc     string
    }{
        {
            "No Controls",
            "",
            "Baseline vulnerability without controls",
        },
        {
            "Perimeter Security",
            "/MAV:A",
            "Firewall limits access to adjacent network",
        },
        {
            "Access Controls",
            "/MAV:A/MPR:L",
            "Basic authentication required",
        },
        {
            "Enhanced Authentication",
            "/MAV:A/MPR:H",
            "Multi-factor authentication implemented",
        },
        {
            "User Awareness",
            "/MAV:A/MPR:H/MUI:R",
            "User training reduces social engineering",
        },
        {
            "Data Protection",
            "/MAV:A/MPR:H/MUI:R/MC:L/MI:L",
            "Encryption and integrity controls",
        },
        {
            "Full Defense",
            "/MAV:L/MAC:H/MPR:H/MUI:R/MS:U/MC:L/MI:L/MA:L",
            "Comprehensive security controls",
        },
    }

    fmt.Println("=== Defense in Depth Analysis ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    for i, layer := range layers {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + layer.controls
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("Layer %d: %s\n", i+1, layer.layer)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Printf("  Controls: %s\n", layer.controls)
        fmt.Printf("  Description: %s\n", layer.desc)
        fmt.Println()
    }
}
```

## Environmental Score Calculation

### Detailed Calculation Breakdown

```go
func explainEnvironmentalCalculation(vector *cvss.Cvss3x) {
    if !vector.HasEnvironmental() {
        fmt.Println("No environmental metrics to analyze")
        return
    }

    calculator := cvss.NewCalculator(vector)
    
    // Get individual scores
    baseScore, _ := calculator.CalculateBaseScore()
    envScore, _ := calculator.CalculateEnvironmentalScore()

    fmt.Println("=== Environmental Score Calculation ===")
    fmt.Printf("Base Score: %.1f\n", baseScore)
    
    env := vector.Cvss3xEnvironmental
    
    // Show requirement multipliers
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

    fmt.Printf("\nRequirement Multipliers:\n")
    fmt.Printf("  Confidentiality Requirement: %.1f\n", crMultiplier)
    fmt.Printf("  Integrity Requirement: %.1f\n", irMultiplier)
    fmt.Printf("  Availability Requirement: %.1f\n", arMultiplier)
    
    // Check for modified base metrics
    hasModified := env.ModifiedAttackVector != nil ||
                   env.ModifiedAttackComplexity != nil ||
                   env.ModifiedPrivilegesRequired != nil ||
                   env.ModifiedUserInteraction != nil ||
                   env.ModifiedScope != nil ||
                   env.ModifiedConfidentialityImpact != nil ||
                   env.ModifiedIntegrityImpact != nil ||
                   env.ModifiedAvailabilityImpact != nil

    if hasModified {
        fmt.Printf("\nModified Base Metrics Present:\n")
        fmt.Printf("  Environmental score calculated using modified metrics\n")
    }
    
    fmt.Printf("\nFinal Environmental Score: %.1f\n", envScore)
}
```

### Step-by-Step Calculation

```go
func stepByStepEnvironmentalCalculation() {
    baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    envVector := baseVector + "/CR:H/IR:M/AR:L/MAV:L/MC:L"
    
    fmt.Println("=== Step-by-Step Environmental Calculation ===")
    fmt.Printf("Vector: %s\n\n", envVector)
    
    parser := parser.NewCvss3xParser(envVector)
    vector, _ := parser.Parse()
    
    calculator := cvss.NewCalculator(vector)
    
    // Step 1: Calculate modified base score
    fmt.Println("Step 1: Calculate Modified Base Score")
    fmt.Println("  Using modified metrics where provided:")
    fmt.Println("  - Modified Attack Vector: Local (instead of Network)")
    fmt.Println("  - Modified Confidentiality: Low (instead of High)")
    
    // Step 2: Apply environmental requirements
    fmt.Println("\nStep 2: Apply Environmental Requirements")
    fmt.Println("  - Confidentiality Requirement: High (1.5x)")
    fmt.Println("  - Integrity Requirement: Medium (1.0x)")
    fmt.Println("  - Availability Requirement: Low (0.5x)")
    
    // Step 3: Final calculation
    envScore, _ := calculator.CalculateEnvironmentalScore()
    fmt.Printf("\nStep 3: Final Environmental Score: %.1f\n", envScore)
}
```

## Practical Applications

### Risk Assessment by Environment

```go
func assessRiskByEnvironment(baseVector string) {
    environments := []struct {
        name         string
        requirements string
        controls     string
        description  string
    }{
        {
            "Production DMZ",
            "/CR:H/IR:H/AR:H",
            "/MAV:A/MPR:L",
            "Internet-facing production with basic controls",
        },
        {
            "Internal Production",
            "/CR:H/IR:H/AR:H", 
            "/MAV:L/MPR:H/MUI:R",
            "Internal production with strong access controls",
        },
        {
            "Development Environment",
            "/CR:M/IR:M/AR:L",
            "/MAV:L/MPR:L",
            "Development environment with test data",
        },
        {
            "Isolated Test Lab",
            "/CR:L/IR:L/AR:L",
            "/MAV:L/MAC:H/MPR:H",
            "Isolated testing environment",
        },
    }

    fmt.Println("=== Risk Assessment by Environment ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    for _, env := range environments {
        vectorStr := baseVector + env.requirements + env.controls
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)

        fmt.Printf("Environment: %s\n", env.name)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Printf("  Requirements: %s\n", env.requirements)
        fmt.Printf("  Controls: %s\n", env.controls)
        fmt.Printf("  Description: %s\n", env.description)
        fmt.Println()
    }
}
```

### Control Effectiveness Analysis

```go
func analyzeControlEffectiveness(baseVector string) {
    controls := []struct {
        control     string
        investment  string
        reduction   string
        description string
    }{
        {
            "Basic Firewall",
            "Low",
            "/MAV:A",
            "Network perimeter protection",
        },
        {
            "WAF + IPS",
            "Medium",
            "/MAV:A/MAC:H",
            "Web application firewall and intrusion prevention",
        },
        {
            "Zero Trust",
            "High",
            "/MAV:L/MPR:H/MUI:R",
            "Zero trust architecture implementation",
        },
        {
            "Full Security Stack",
            "Very High",
            "/MAV:L/MAC:H/MPR:H/MUI:R/MC:L/MI:L/MA:L",
            "Comprehensive security controls",
        },
    }

    fmt.Println("=== Control Effectiveness Analysis ===")
    fmt.Printf("Base Vector: %s\n\n", baseVector)

    // Calculate base score
    baseParser := parser.NewCvss3xParser(baseVector)
    baseParsed, _ := baseParser.Parse()
    baseCalc := cvss.NewCalculator(baseParsed)
    baseScore, _ := baseCalc.Calculate()

    fmt.Printf("Base Score: %.1f\n\n", baseScore)

    for _, control := range controls {
        vectorStr := baseVector + "/CR:H/IR:H/AR:H" + control.reduction
        
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        severity := calculator.GetSeverityRating(score)
        reduction := baseScore - score
        effectiveness := (reduction / baseScore) * 100

        fmt.Printf("Control: %s\n", control.control)
        fmt.Printf("  Investment: %s\n", control.investment)
        fmt.Printf("  Score: %.1f (%s)\n", score, severity)
        fmt.Printf("  Reduction: %.1f points (%.1f%% effective)\n", reduction, effectiveness)
        fmt.Printf("  Description: %s\n", control.description)
        fmt.Println()
    }
}
```

## Testing and Validation

### Environmental Metrics Validation

```go
func validateEnvironmentalMetrics(vector *cvss.Cvss3x) []string {
    var issues []string

    if !vector.HasEnvironmental() {
        return issues
    }

    env := vector.Cvss3xEnvironmental

    // Validate requirement metrics
    if env.ConfidentialityRequirement != nil {
        value := env.ConfidentialityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("Invalid Confidentiality Requirement: %c", value))
        }
    }

    if env.IntegrityRequirement != nil {
        value := env.IntegrityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("Invalid Integrity Requirement: %c", value))
        }
    }

    if env.AvailabilityRequirement != nil {
        value := env.AvailabilityRequirement.GetShortValue()
        if value != 'X' && value != 'L' && value != 'M' && value != 'H' {
            issues = append(issues, fmt.Sprintf("Invalid Availability Requirement: %c", value))
        }
    }

    // Validate modified base metrics (similar validation as base metrics)
    // ... additional validation logic

    return issues
}
```

### Environmental Scenarios Testing

```go
func testEnvironmentalScenarios() {
    testCases := []struct {
        name        string
        vector      string
        expectError bool
        minScore    float64
        maxScore    float64
    }{
        {
            "High requirements only",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H",
            false,
            9.0,
            10.0,
        },
        {
            "Low requirements only",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L",
            false,
            5.0,
            8.0,
        },
        {
            "Strong controls",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MC:L/MI:L/MA:L",
            false,
            2.0,
            5.0,
        },
    }

    fmt.Println("=== Environmental Scenarios Testing ===")

    for _, tc := range testCases {
        fmt.Printf("\nTest: %s\n", tc.name)
        fmt.Printf("Vector: %s\n", tc.vector)

        parser := parser.NewCvss3xParser(tc.vector)
        vector, err := parser.Parse()

        if tc.expectError {
            if err != nil {
                fmt.Printf("✓ Expected error: %v\n", err)
            } else {
                fmt.Printf("✗ Expected error but parsing succeeded\n")
            }
        } else {
            if err != nil {
                fmt.Printf("✗ Unexpected error: %v\n", err)
            } else {
                calculator := cvss.NewCalculator(vector)
                score, _ := calculator.Calculate()
                
                if score >= tc.minScore && score <= tc.maxScore {
                    fmt.Printf("✓ Score %.1f within expected range [%.1f-%.1f]\n", 
                        score, tc.minScore, tc.maxScore)
                } else {
                    fmt.Printf("✗ Score %.1f outside expected range [%.1f-%.1f]\n", 
                        score, tc.minScore, tc.maxScore)
                }
            }
        }
    }
}
```

## Next Steps

After mastering environmental metrics, you can explore:

- [Vector Comparison](/examples/comparison) - Comparing different environmental configurations
- [Severity Levels](/examples/severity) - Understanding severity in different contexts
- [Advanced Examples](/examples/edge-cases) - Complex environmental scenarios

## Related Documentation

- [Environmental Metrics API](/api/cvss/calculator) - Detailed API reference
- [CVSS Specification](https://www.first.org/cvss/) - Official CVSS documentation
- [Risk Assessment Guide](/examples/risk-assessment) - Comprehensive risk assessment examples
