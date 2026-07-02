# Cvss3x Data Structure

The `Cvss3x` struct is the core data structure in CVSS Skills, representing a complete CVSS 3.x vector with all its metrics and metadata.

## Type Definition

`Cvss3x` embeds the three metric groups as pointers and carries the version numbers. The fields are unexported-tag-free; JSON serialization is handled by a custom `MarshalJSON` (see [JSON Support](/api/cvss/json)), not by struct tags:

```go
type Cvss3x struct {
    *Cvss3xBase           // embedded — base metrics (required)
    *Cvss3xTemporal       // embedded — temporal metrics (optional, nil if absent)
    *Cvss3xEnvironmental  // embedded — environmental metrics (optional, nil if absent)

    MajorVersion int      // always 3
    MinorVersion int      // 0 (CVSS 3.0) or 1 (CVSS 3.1)
}
```

## Core Components

### Version Information

```go
// MajorVersion is always 3; MinorVersion is 0 (v3.0) or 1 (v3.1).
type Cvss3x struct {
    MajorVersion int
    MinorVersion int
    // ...
}
```

**Supported Versions:**
- CVSS 3.0: `MajorVersion: 3, MinorVersion: 0`
- CVSS 3.1: `MajorVersion: 3, MinorVersion: 1`

### Base Metrics

```go
type Cvss3xBase struct {
    AttackVector       vector.Vector
    AttackComplexity   vector.Vector
    PrivilegesRequired vector.Vector
    UserInteraction    vector.Vector
    Scope              vector.Vector
    Confidentiality    vector.Vector
    Integrity          vector.Vector
    Availability       vector.Vector
}
```

`vector.Vector` is an interface. Each metric value is a predeclared pointer variable in `pkg/vector` (e.g. `vector.AttackVectorNetwork`, `vector.ConfidentialityHigh`) — assign the variable directly, do **not** take its address or instantiate it.

**Required Metrics:**
- **Attack Vector (AV)**: Network, Adjacent, Local, Physical
- **Attack Complexity (AC)**: Low, High
- **Privileges Required (PR)**: None, Low, High
- **User Interaction (UI)**: None, Required
- **Scope (S)**: Unchanged, Changed
- **Confidentiality Impact (C)**: None, Low, High
- **Integrity Impact (I)**: None, Low, High
- **Availability Impact (A)**: None, Low, High

### Temporal Metrics

```go
type Cvss3xTemporal struct {
    ExploitCodeMaturity vector.Vector
    RemediationLevel    vector.Vector
    ReportConfidence    vector.Vector
}
```

**Optional Metrics:**
- **Exploit Code Maturity (E)**: Not Defined, Unproven, Proof-of-Concept, Functional, High
- **Remediation Level (RL)**: Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable
- **Report Confidence (RC)**: Not Defined, Unknown, Reasonable, Confirmed

### Environmental Metrics

```go
type Cvss3xEnvironmental struct {
    // Environmental Requirements
    ConfidentialityRequirement vector.Vector
    IntegrityRequirement       vector.Vector
    AvailabilityRequirement    vector.Vector

    // Modified Base Metrics
    ModifiedAttackVector       vector.Vector
    ModifiedAttackComplexity   vector.Vector
    ModifiedPrivilegesRequired vector.Vector
    ModifiedUserInteraction    vector.Vector
    ModifiedScope              vector.Vector
    ModifiedConfidentiality    vector.Vector
    ModifiedIntegrity          vector.Vector
    ModifiedAvailability       vector.Vector
}
```

## Constructor Functions

### NewCvss3x

```go
func NewCvss3x() *Cvss3x
```

Creates a new CVSS 3.x instance with an empty base group and `nil` temporal/environmental groups. The version defaults to 3.1; override it with `SetMetricValue` / the Builder, or parse a string that carries the `CVSS:3.0` prefix.

**Returns:**
- `*Cvss3x`: New CVSS 3.x instance (base group allocated, temporal/environmental nil)

**Example:**
```go
cv := cvss.NewCvss3x() // empty vector (base group allocated; version defaults to 0 — set it or use Builder)
```

::: tip Prefer the Builder or Parser
Constructing a `Cvss3x` by hand requires assigning every metric field. In practice, use `cvss.NewBuilder().Version(3,1).AV('N')…MustBuild()` or `parser.ParseString("CVSS:3.1/…")` instead.
:::

## Main Methods

### String

```go
func (x *Cvss3x) String() string
```

Returns the canonical CVSS vector string representation.

**Returns:**
- `string`: CVSS vector string

**Example:**
```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
fmt.Println(cv.String()) // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### IsComplete

```go
func (x *Cvss3x) IsComplete() bool
```

Checks whether all 8 required base metrics are set. Does not validate values or check version/optional metrics — use `Validate()` for full structural validation.

**Returns:**
- `bool`: True if every base metric is non-nil

**Example:**
```go
if cv.IsComplete() {
    fmt.Println("all base metrics are set")
} else {
    fmt.Println("incomplete; missing:", cv.MissingMetrics())
}
```

### Version

```go
func (x *Cvss3x) Version() string
```

Returns the version string formatted as `"<major>.<minor>"`.

**Returns:**
- `string`: Version string (e.g., `"3.1"`)

**Example:**
```go
fmt.Printf("CVSS Version: %s\n", cv.Version()) // "3.1"
```

### HasTemporalMetrics

```go
func (x *Cvss3x) HasTemporalMetrics() bool
```

Checks if any temporal metric (`E`, `RL`, `RC`) is set.

**Returns:**
- `bool`: True if at least one temporal metric is present

**Example:**
```go
if cv.HasTemporalMetrics() {
    fmt.Println("vector includes temporal metrics")
}
```

### HasEnvironmentalMetrics

```go
func (x *Cvss3x) HasEnvironmentalMetrics() bool
```

Checks if any environmental metric is set.

**Returns:**
- `bool`: True if at least one environmental metric is present

**Example:**
```go
if cv.HasEnvironmentalMetrics() {
    fmt.Println("vector includes environmental metrics")
}
```

## Usage Examples

### Creating a Complete Vector

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    // Create an empty 3.1 vector (NewCvss3x allocates the base group)
    cv := cvss.NewCvss3x()
    cv.MajorVersion = 3
    cv.MinorVersion = 1

    // Set base metrics — assign the predeclared value variables directly
    cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
    cv.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
    cv.Cvss3xBase.PrivilegesRequired = vector.PrivilegesRequiredNone
    cv.Cvss3xBase.UserInteraction = vector.UserInteractionNone
    cv.Cvss3xBase.Scope = vector.ScopeUnchanged
    cv.Cvss3xBase.Confidentiality = vector.ConfidentialityHigh
    cv.Cvss3xBase.Integrity = vector.IntegrityHigh
    cv.Cvss3xBase.Availability = vector.AvailabilityHigh

    // Add temporal metrics (optional)
    cv.Cvss3xTemporal = &cvss.Cvss3xTemporal{
        ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional,
        RemediationLevel:    vector.RemediationLevelOfficialFix,
        ReportConfidence:    vector.ReportConfidenceConfirmed,
    }

    // Output
    fmt.Printf("CVSS Vector: %s\n", cv.String())
    fmt.Printf("Version: %s\n", cv.Version())
    fmt.Printf("Complete: %t\n", cv.IsComplete())
    fmt.Printf("Has Temporal: %t\n", cv.HasTemporalMetrics())
}
```

::: tip Prefer the Builder for hand construction
The fluent `cvss.NewBuilder().Version(3, 1).AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').MustBuild()` is shorter and validates each metric value as it is set.
:::

### Vector Validation

```go
func validateCvssVector(cvss *cvss.Cvss3x) error {
    if cvss == nil {
        return fmt.Errorf("CVSS vector is nil")
    }
    
    if cvss.MajorVersion != 3 {
        return fmt.Errorf("unsupported major version: %d", cvss.MajorVersion)
    }
    
    if cvss.MinorVersion != 0 && cvss.MinorVersion != 1 {
        return fmt.Errorf("unsupported minor version: %d", cvss.MinorVersion)
    }
    
    if cvss.Cvss3xBase == nil {
        return fmt.Errorf("base metrics are required")
    }
    
    // Validate required base metrics
    if cvss.Cvss3xBase.AttackVector == nil {
        return fmt.Errorf("attack vector is required")
    }
    
    if cvss.Cvss3xBase.AttackComplexity == nil {
        return fmt.Errorf("attack complexity is required")
    }
    
    // ... validate other required metrics
    
    return nil
}
```

### Vector Comparison

```go
func compareVectors(v1, v2 *cvss.Cvss3x) {
    fmt.Printf("Comparing vectors:\n")
    fmt.Printf("  Vector 1: %s\n", v1.String())
    fmt.Printf("  Vector 2: %s\n", v2.String())
    
    // Compare versions
    if v1.Version() != v2.Version() {
        fmt.Printf("  Different versions: %s vs %s\n", v1.Version(), v2.Version())
    }
    
    // Compare base metrics
    if v1.Cvss3xBase.AttackVector.GetShortValue() != v2.Cvss3xBase.AttackVector.GetShortValue() {
        fmt.Printf("  Different attack vectors: %c vs %c\n", 
            v1.Cvss3xBase.AttackVector.GetShortValue(),
            v2.Cvss3xBase.AttackVector.GetShortValue())
    }
    
    // ... compare other metrics
}
```

### Vector Modification

```go
func modifyVector(cv *cvss.Cvss3x) *cvss.Cvss3x {
    // Deep copy — Clone() duplicates the base/temporal/env groups so the
    // original is not affected. (A plain `modified := *cv` would share the
    // embedded *Cvss3xBase pointer and mutate the original.)
    modified := cv.Clone()

    // Modify attack vector
    modified.Cvss3xBase.AttackVector = vector.AttackVectorLocal

    // Add temporal metrics if not present
    if modified.Cvss3xTemporal == nil {
        modified.Cvss3xTemporal = &cvss.Cvss3xTemporal{
            ExploitCodeMaturity: vector.ExploitCodeMaturityProofOfConcept,
            RemediationLevel:    vector.RemediationLevelWorkaround,
            ReportConfidence:    vector.ReportConfidenceReasonable,
        }
    }

    return modified
}
```

## JSON Serialization

### Marshal to JSON

```go
import "encoding/json"

func vectorToJSON(cvss *cvss.Cvss3x) ([]byte, error) {
    return json.MarshalIndent(cvss, "", "  ")
}

// Usage
jsonData, err := vectorToJSON(cvss)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

### Unmarshal from JSON

```go
func vectorFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var cvss cvss.Cvss3x
    err := json.Unmarshal(jsonData, &cvss)
    return &cvss, err
}

// Usage
cvss, err := vectorFromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}
```

## Best Practices

### 1. Immutability

```go
// Construct a fully-populated, immutable vector
func createImmutableVector() *cvss.Cvss3x {
    cv := cvss.NewCvss3x()
    cv.MajorVersion = 3
    cv.MinorVersion = 1

    cv.Cvss3xBase = &cvss.Cvss3xBase{
        AttackVector:     vector.AttackVectorNetwork,
        AttackComplexity: vector.AttackComplexityLow,
        PrivilegesRequired: vector.PrivilegesRequiredNone,
        UserInteraction:  vector.UserInteractionNone,
        Scope:            vector.ScopeUnchanged,
        Confidentiality:  vector.ConfidentialityHigh,
        Integrity:        vector.IntegrityHigh,
        Availability:     vector.AvailabilityHigh,
    }

    return cv
}
```

### 2. Validation

```go
func createValidatedVector() (*cvss.Cvss3x, error) {
    cvss := createImmutableVector()
    
    if err := validateCvssVector(cvss); err != nil {
        return nil, fmt.Errorf("vector validation failed: %w", err)
    }
    
    return cvss, nil
}
```

### 3. Builder Pattern

CVSS Skills ships a fluent `Cvss3xBuilder` (`cvss.NewBuilder()`). Each method takes a `rune` short-value (e.g. `'N'` for AV Network) and validates it immediately; `Build()` returns an error, `MustBuild()` panics on error:

```go
// pkg/cvss/builder.go
type Cvss3xBuilder struct { /* unexported */ }

func NewBuilder() *Cvss3xBuilder
func (b *Cvss3xBuilder) Version(major, minor int) *Cvss3xBuilder
func (b *Cvss3xBuilder) AV(val rune) *Cvss3xBuilder   // Attack Vector
func (b *Cvss3xBuilder) AC(val rune) *Cvss3xBuilder   // Attack Complexity
func (b *Cvss3xBuilder) PR(val rune) *Cvss3xBuilder   // Privileges Required
func (b *Cvss3xBuilder) UI(val rune) *Cvss3xBuilder   // User Interaction
func (b *Cvss3xBuilder) S(val rune) *Cvss3xBuilder    // Scope
func (b *Cvss3xBuilder) C(val rune) *Cvss3xBuilder    // Confidentiality
func (b *Cvss3xBuilder) I(val rune) *Cvss3xBuilder    // Integrity
func (b *Cvss3xBuilder) A(val rune) *Cvss3xBuilder    // Availability
// …plus E/RL/RC and modified-metric (MAV/MAC/…) setters
func (b *Cvss3xBuilder) Build() (*Cvss3x, error)
func (b *Cvss3xBuilder) MustBuild() *Cvss3x
```

**Usage:**
```go
cv, err := cvss.NewBuilder().Version(3, 1).
    AV('N').AC('L').PR('N').UI('N').S('U').
    C('H').I('H').A('H').
    Build()
if err != nil {
    log.Fatal(err)
}
fmt.Println(cv.String()) // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Related Documentation

- [Calculator](/api/cvss/calculator) - Score calculation
- [DistanceCalculator](/api/cvss/distance) - Vector comparison
- [JSON Support](/api/cvss/json) - Serialization
- [Parser](/api/parser/cvss3x-parser) - String parsing
