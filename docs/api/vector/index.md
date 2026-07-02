# vector Package

The `vector` package provides unified interfaces and concrete implementations for all CVSS metrics. It defines the behavior and properties of all CVSS 3.x metrics, providing the foundational data structures for parsers and calculators.

## Package Overview

```go
import "github.com/scagogogo/cvss-skills/pkg/vector"
```

## Core Interface

### Vector Interface

All CVSS metrics implement the `Vector` interface:

```go
type Vector interface {
    GetGroupName() string    // "Base Metrics" / "Temporal Metrics" / "Environmental Metrics"
    GetShortName() string    // e.g. "AV"
    GetLongName() string     // e.g. "Attack Vector"
    GetShortValue() rune     // e.g. 'N'
    GetLongValue() string    // e.g. "Network"
    GetDescription() string  // CVSS spec description
    GetScore() float64       // score weight (1.0 for Not Defined)
    IsNotDefined() bool      // whether the value is "Not Defined" (X)
    String() string          // e.g. "AV:N"
}
```

Detailed documentation: [Vector Interface](/api/vector/interface)

## Metric Categories

### Base Metrics

Base metrics describe the intrinsic characteristics of a vulnerability that do not change over time or environment.

#### Exploitability Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Attack Vector | AV | `AttackVector*` | Network, Adjacent, Local, Physical |
| Attack Complexity | AC | `AttackComplexity*` | Low, High |
| Privileges Required | PR | `PrivilegesRequired*` | None, Low, High |
| User Interaction | UI | `UserInteraction*` | None, Required |

#### Impact Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Scope | S | `Scope*` | Unchanged, Changed |
| Confidentiality Impact | C | `Confidentiality*` | None, Low, High |
| Integrity Impact | I | `Integrity*` | None, Low, High |
| Availability Impact | A | `Availability*` | None, Low, High |

### Temporal Metrics

Temporal metrics reflect the characteristics of a vulnerability that change over time.

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Exploit Code Maturity | E | `ExploitCodeMaturity*` | Not Defined, Unproven, Proof-of-Concept, Functional, High |
| Remediation Level | RL | `RemediationLevel*` | Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable |
| Report Confidence | RC | `ReportConfidence*` | Not Defined, Unknown, Reasonable, Confirmed |

### Environmental Metrics

Environmental metrics allow analysts to customize CVSS scores according to specific environments.

#### Environmental Requirement Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Confidentiality Requirement | CR | `ConfidentialityRequirement*` | Not Defined, Low, Medium, High |
| Integrity Requirement | IR | `IntegrityRequirement*` | Not Defined, Low, Medium, High |
| Availability Requirement | AR | `AvailabilityRequirement*` | Not Defined, Low, Medium, High |

#### Modified Base Metrics

All base metrics have corresponding modified versions, prefixed with `Modified`:

- `ModifiedAttackVector*`
- `ModifiedAttackComplexity*`
- `ModifiedPrivilegesRequired*`
- etc...

## Usage Examples

### Creating Metric Instances

Each legal metric value is exposed as a pre-defined package-level variable (a singleton). Reference it directly — there is no need to construct it:

```go
// Attack Vector = Network
attackVector := vector.AttackVectorNetwork
fmt.Printf("Attack Vector: %s (%s)\n",
    attackVector.GetLongValue(),
    attackVector.GetDescription())

// Attack Complexity = Low
attackComplexity := vector.AttackComplexityLow
fmt.Printf("Attack Complexity: %s (Score: %.2f)\n",
    attackComplexity.GetLongValue(),
    attackComplexity.GetScore())
```

Alternatively, resolve a value from its short name/value with a [factory function](/api/vector/interface#factory-functions):

```go
av, err := vector.GetVectorByShortName("AV", "N")
if err != nil {
    log.Fatal(err)
}
fmt.Println(av.String()) // AV:N
```

### Using Interface

```go
func printVectorInfo(v vector.Vector) {
    fmt.Printf("Metric: %s (%s)\n", v.GetLongName(), v.GetShortName())
    fmt.Printf("  Group: %s\n", v.GetGroupName())
    fmt.Printf("  Value: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  Score: %.2f\n", v.GetScore())
    fmt.Printf("  Not defined: %v\n", v.IsNotDefined())
    fmt.Printf("  String: %s\n", v.String())
}

// Usage example
printVectorInfo(vector.AttackVectorNetwork)
```

### Vector Factory

The package provides factory functions that resolve a metric value from its short value, returning an error for an unknown value. There is one factory per metric (e.g. `GetAttackVector`, `GetExploitCodeMaturity`) plus the generic `GetVectorByShortName`:

```go
// Per-metric factory
av, err := vector.GetAttackVector('N')
if err != nil {
    log.Fatal(err)
}
fmt.Println(av.String()) // AV:N

// Generic factory by short name + value string
e, err := vector.GetVectorByShortName("E", "F")
if err != nil {
    log.Fatal(err)
}
fmt.Println(e.String()) // E:F
```

## Metric Details

Each metric value is a pre-defined variable of a type that embeds `*VectorImpl` (see [Vector Interface](/api/vector/interface)). The tables below list the canonical singletons and their score weights.

### Attack Vector

Describes how an attacker accesses the vulnerable component.

| Singleton | Short Value | Long Value | Score |
|------------|-------------|------------|-------|
| `AttackVectorNetwork` | N | Network | 0.85 |
| `AttackVectorAdjacent` | A | Adjacent | 0.62 |
| `AttackVectorLocal` | L | Local | 0.55 |
| `AttackVectorPhysical` | P | Physical | 0.2 |

```go
av := vector.AttackVectorNetwork
fmt.Printf("%c %.2f\n", av.GetShortValue(), av.GetScore()) // N 0.85
```

### Attack Complexity

Describes the conditions required for a successful attack.

| Singleton | Short Value | Long Value | Score |
|------------|-------------|------------|-------|
| `AttackComplexityLow` | L | Low | 0.77 |
| `AttackComplexityHigh` | H | High | 0.44 |

### Impact Metrics

Impact metrics describe the degree of impact a successful attack has on the system.

| Singleton | Short Value | Long Value | Score |
|------------|-------------|------------|-------|
| `ConfidentialityHigh` | H | High | 0.56 |
| `ConfidentialityLow` | L | Low | 0.22 |
| `ConfidentialityNone` | N | None | 0.0 |

::: tip Scope-dependent metrics
Privileges Required (`PR`) is the only base metric whose weight depends on Scope. Use `vector.GetPrivilegesRequiredScore(pr, scopeChanged)` rather than `pr.GetScore()` — see [Vector Interface](/api/vector/interface#getprivilegesrequiredscore).
:::

## Vector Validation

### Basic Validation

```go
func validateVector(v vector.Vector) error {
    if v.GetShortName() == "" {
        return fmt.Errorf("metric short name cannot be empty")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("metric value cannot be empty")
    }
    
    score := v.GetScore()
    if score < 0 || score > 1 {
        return fmt.Errorf("metric score must be between 0-1, current value: %.2f", score)
    }
    
    return nil
}
```

### Batch Validation

```go
func validateVectors(vectors []vector.Vector) []error {
    var errors []error
    
    for i, v := range vectors {
        if err := validateVector(v); err != nil {
            errors = append(errors, fmt.Errorf("vector %d validation failed: %w", i, err))
        }
    }
    
    return errors
}
```

## Vector Comparison

### Basic Comparison

```go
func compareVectors(v1, v2 vector.Vector) {
    fmt.Printf("Comparing %s and %s:\n", v1.String(), v2.String())
    
    if v1.GetShortName() != v2.GetShortName() {
        fmt.Println("  Different metric types, cannot compare")
        return
    }
    
    score1 := v1.GetScore()
    score2 := v2.GetScore()
    
    if score1 > score2 {
        fmt.Printf("  %s (%.2f) > %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else if score1 < score2 {
        fmt.Printf("  %s (%.2f) < %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else {
        fmt.Printf("  %s = %s (%.2f)\n", 
            v1.GetDescription(), v2.GetDescription(), score1)
    }
}
```

### Vector Grouping

```go
func groupVectorsByType(vectors []vector.Vector) map[string][]vector.Vector {
    groups := make(map[string][]vector.Vector)
    
    for _, v := range vectors {
        groupName := v.GetGroupName()
        groups[groupName] = append(groups[groupName], v)
    }
    
    return groups
}
```

## Extension and Customization

### Custom Vector

To implement a custom metric, embed `*vector.VectorImpl` — it already provides every `Vector` interface method, so you only fill in the fields:

```go
// Custom vector implementation backed by VectorImpl
type CustomVector struct {
    *vector.VectorImpl
}

cv := &CustomVector{
    VectorImpl: &vector.VectorImpl{
        GroupName:   "Base Metrics",
        ShortName:   "AV",
        LongName:    "Attack Vector",
        ShortValue:  'N',
        LongValue:   "Network",
        Description: "custom",
        Score:       0.85,
    },
}
fmt.Println(cv.String())        // AV:N
fmt.Println(cv.IsNotDefined())  // false
```

### Vector Registry

```go
type VectorRegistry struct {
    vectors map[string]map[rune]vector.Vector
}

func NewVectorRegistry() *VectorRegistry {
    return &VectorRegistry{
        vectors: make(map[string]map[rune]vector.Vector),
    }
}

func (r *VectorRegistry) Register(shortName string, value rune, v vector.Vector) {
    if r.vectors[shortName] == nil {
        r.vectors[shortName] = make(map[rune]vector.Vector)
    }
    r.vectors[shortName][value] = v
}

func (r *VectorRegistry) Get(shortName string, value rune) (vector.Vector, bool) {
    if group, exists := r.vectors[shortName]; exists {
        if v, found := group[value]; found {
            return v, true
        }
    }
    return nil, false
}
```

## Performance Optimization

### Vector Caching

```go
var vectorCache = make(map[string]vector.Vector)
var cacheMutex sync.RWMutex

func getCachedVector(key string) (vector.Vector, bool) {
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()
    
    v, exists := vectorCache[key]
    return v, exists
}

func setCachedVector(key string, v vector.Vector) {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    vectorCache[key] = v
}
```

### No Object Pool Needed

The pre-defined singletons are immutable package-level values shared by all callers — there is nothing to pool. Resolving a value via the factory functions is a cheap `switch` that returns the existing singleton, so each call costs essentially a pointer copy. Avoid wrapping them in a `sync.Pool`; just call `vector.GetAttackVector('N')` or reference `vector.AttackVectorNetwork` directly.

## Best Practices

### 1. Type Safety

```go
func getAttackVectorScore(v vector.Vector) (float64, error) {
    if v.GetShortName() != "AV" {
        return 0, fmt.Errorf("not an attack vector metric")
    }
    return v.GetScore(), nil
}
```

### 2. Null Value Handling

```go
func safeGetScore(v vector.Vector) float64 {
    if v == nil {
        return 0.0
    }
    return v.GetScore()
}
```

### 3. Interface Composition

The `Vector` interface is intentionally flat — it does not split into sub-interfaces. If you need a narrower view (e.g. only the scoring methods), define a local interface in your own code and assert against it:

```go
// Local, application-specific narrower interface
type Scorer interface {
    GetScore() float64
    IsNotDefined() bool
}

func scoreOf(s Scorer) float64 {
    if s.IsNotDefined() {
        return 1.0 // no-op weight
    }
    return s.GetScore()
}
```

## Related Documentation

- [Vector Interface Details](/api/vector/interface)
- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Parser](/api/parser/cvss3x-parser)
- [Usage Examples](/examples/basic)
