# Basic Usage Examples

This example demonstrates the most basic usage of CVSS Skills: parsing CVSS vector strings and calculating scores.

## Example Code

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // =====================================================
    // CVSS Skills Basic Usage Example
    // Demonstrates how to parse CVSS vector strings and get basic information and scores
    // =====================================================

    // Example CVSS vector string - Critical level, score 9.8
    cvssVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    fmt.Println("Example CVSS Vector:", cvssVector)
    fmt.Println("=====================================================")

    // Step 1: Create parser
    p := parser.NewCvss3xParser(cvssVector)
    fmt.Println("✓ Parser created successfully")

    // Step 2: Parse CVSS vector
    parsedVector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }
    fmt.Println("✓ Vector parsed successfully")

    // Step 3: Display basic information
    fmt.Printf("CVSS Version: %d.%d\n", parsedVector.MajorVersion, parsedVector.MinorVersion)
    fmt.Printf("Vector String: %s\n", parsedVector.String())

    // Step 4: Create calculator
    calculator := cvss.NewCalculator(parsedVector)
    fmt.Println("✓ Calculator created successfully")

    // Step 5: Calculate score
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("Score calculation failed: %v", err)
    }

    // Step 6: Get severity rating
    severity := calculator.GetSeverityRating(score)

    // Step 7: Display results
    fmt.Println("=====================================================")
    fmt.Println("CALCULATION RESULTS:")
    fmt.Printf("Base Score: %.1f\n", score)
    fmt.Printf("Severity Level: %s\n", severity)
    fmt.Println("=====================================================")

    // Additional information: Display individual metric details
    fmt.Println("\nMETRIC DETAILS:")
    fmt.Printf("Attack Vector: %s (%s)\n", 
        parsedVector.Cvss3xBase.AttackVector.GetLongValue(),
        parsedVector.Cvss3xBase.AttackVector.GetDescription())
    
    fmt.Printf("Attack Complexity: %s (%s)\n", 
        parsedVector.Cvss3xBase.AttackComplexity.GetLongValue(),
        parsedVector.Cvss3xBase.AttackComplexity.GetDescription())
    
    fmt.Printf("Privileges Required: %s (%s)\n", 
        parsedVector.Cvss3xBase.PrivilegesRequired.GetLongValue(),
        parsedVector.Cvss3xBase.PrivilegesRequired.GetDescription())
    
    fmt.Printf("User Interaction: %s (%s)\n", 
        parsedVector.Cvss3xBase.UserInteraction.GetLongValue(),
        parsedVector.Cvss3xBase.UserInteraction.GetDescription())
    
    fmt.Printf("Scope: %s (%s)\n", 
        parsedVector.Cvss3xBase.Scope.GetLongValue(),
        parsedVector.Cvss3xBase.Scope.GetDescription())
    
    fmt.Printf("Confidentiality Impact: %s (%s)\n", 
        parsedVector.Cvss3xBase.Confidentiality.GetLongValue(),
        parsedVector.Cvss3xBase.Confidentiality.GetDescription())
    
    fmt.Printf("Integrity Impact: %s (%s)\n", 
        parsedVector.Cvss3xBase.Integrity.GetLongValue(),
        parsedVector.Cvss3xBase.Integrity.GetDescription())
    
    fmt.Printf("Availability Impact: %s (%s)\n", 
        parsedVector.Cvss3xBase.Availability.GetLongValue(),
        parsedVector.Cvss3xBase.Availability.GetDescription())
}
```

## Expected Output

When you run this example, you should see output similar to:

```
Example CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
=====================================================
✓ Parser created successfully
✓ Vector parsed successfully
CVSS Version: 3.1
Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
✓ Calculator created successfully
=====================================================
CALCULATION RESULTS:
Base Score: 9.8
Severity Level: Critical
=====================================================

METRIC DETAILS:
Attack Vector: Network (The vulnerable component is bound to the network stack...)
Attack Complexity: Low (Specialized access conditions or extenuating circumstances...)
Privileges Required: None (The attacker is unauthorized prior to attack...)
User Interaction: None (The vulnerable system can be exploited without interaction...)
Scope: Unchanged (An exploited vulnerability can only affect resources...)
Confidentiality Impact: High (There is a total loss of confidentiality...)
Integrity Impact: High (There is a total loss of integrity...)
Availability Impact: High (There is a total loss of availability...)
```

## Step-by-Step Explanation

### Step 1: Import Required Packages

```go
import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)
```

- `cvss` package: Contains the calculator and data structures
- `parser` package: Contains the CVSS vector string parser

### Step 2: Create Parser

```go
p := parser.NewCvss3xParser(cvssVector)
```

The parser is responsible for converting CVSS vector strings into structured data objects.

### Step 3: Parse Vector

```go
parsedVector, err := p.Parse()
```

This converts the string into a `Cvss3x` object containing all metric information.

### Step 4: Create Calculator

```go
calculator := cvss.NewCalculator(parsedVector)
```

The calculator uses the parsed vector to compute CVSS scores.

### Step 5: Calculate Score

```go
score, err := calculator.Calculate()
```

This computes the final CVSS score based on the metrics.

### Step 6: Get Severity Rating

```go
severity := calculator.GetSeverityRating(score)
```

Converts the numerical score to a human-readable severity level.

## Common Variations

### Different Vector Examples

```go
// Low severity example
lowVector := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

// Medium severity example
mediumVector := "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"

// High severity example
highVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

// Critical severity example
criticalVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### Batch Processing

```go
func processMultipleVectors() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    }

    for i, vectorStr := range vectors {
        fmt.Printf("\n--- Processing Vector %d ---\n", i+1)
        
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }

        severity := calculator.GetSeverityRating(score)
        fmt.Printf("Vector: %s\n", vectorStr)
        fmt.Printf("Score: %.1f (%s)\n", score, severity)
    }
}
```

### Error Handling

```go
func safeParseAndCalculate(vectorStr string) {
    // Input validation
    if vectorStr == "" {
        fmt.Println("Error: Vector string cannot be empty")
        return
    }

    // Parse with error handling
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        return
    }

    // Validate parsed vector (Check returns the first missing/invalid metric)
    if err := vector.Check(); err != nil {
        fmt.Printf("Invalid vector: %v\n", err)
        return
    }

    // Calculate with error handling
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        fmt.Printf("Calculation error: %v\n", err)
        return
    }

    // Success
    severity := calculator.GetSeverityRating(score)
    fmt.Printf("Success: %s -> %.1f (%s)\n", vectorStr, score, severity)
}
```

## Running the Example

1. **Save the code** to a file named `basic_example.go`

2. **Initialize Go module** (if not already done):
   ```bash
   go mod init cvss-example
   go get github.com/scagogogo/cvss-skills
   ```

3. **Run the example**:
   ```bash
   go run basic_example.go
   ```

## Next Steps

After understanding this basic example, you can explore:

- [Vector Parsing Examples](/examples/parsing) - Different vector formats
- [JSON Output Examples](/examples/json) - Data serialization
- [Distance Calculation Examples](/examples/distance) - Vector comparison
- [Advanced Examples](/examples/edge-cases) - Error handling and edge cases

## Common Issues

### Import Path Errors

Make sure you're using the correct import path:
```go
"github.com/scagogogo/cvss-skills/pkg/cvss"
"github.com/scagogogo/cvss-skills/pkg/parser"
```

### Invalid Vector Strings

Ensure your CVSS vector strings follow the correct format:
- Start with `CVSS:3.0/` or `CVSS:3.1/`
- Include all required base metrics
- Use valid metric values

### Nil Pointer Errors

Always check for errors after parsing:
```go
vector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    // Handle error
    return
}
// Now safe to use vector
```
