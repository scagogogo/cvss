# cvss Package

The `cvss` package is the core package of CVSS Skills, providing data structures, score calculation, and analysis functions for CVSS 3.x vectors.

## Package Overview

```go
import "github.com/scagogogo/cvss-skills/pkg/cvss"
```

## Main Types

### Core Structures

| Type | Description | Documentation Link |
|------|-------------|-------------------|
| `Cvss3x` | Main data structure for CVSS 3.x vectors | [Detailed Documentation](/api/cvss/cvss3x) |
| `Cvss3xBase` | Base metrics group | [Detailed Documentation](/api/cvss/cvss3x) |
| `Cvss3xTemporal` | Temporal metrics group | [Detailed Documentation](/api/cvss/cvss3x) |
| `Cvss3xEnvironmental` | Environmental metrics group | [Detailed Documentation](/api/cvss/cvss3x) |

### Calculators

| Type | Description | Documentation Link |
|------|-------------|-------------------|
| `Calculator` | CVSS score calculator | [Detailed Documentation](/api/cvss/calculator) |
| `DistanceCalculator` | Vector distance calculator | [Detailed Documentation](/api/cvss/distance) |

## Quick Examples

### Creating CVSS Vectors

```go
// Manually create vector
cvssVector := cvss.NewCvss3x()
cvssVector.MajorVersion = 3
cvssVector.MinorVersion = 1

// Set base metrics
cvssVector.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
cvssVector.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
// ... set other metrics
```

### Score Calculation

```go
// Create calculator
calculator := cvss.NewCalculator(cvssVector)

// Calculate base score
score, err := calculator.Calculate()
if err != nil {
    log.Fatalf("Calculation failed: %v", err)
}

fmt.Printf("CVSS Score: %.1f\n", score)
fmt.Printf("Severity: %s\n", calculator.GetSeverityRating(score))
```

### Vector Distance Calculation

```go
// Calculate distance between two vectors
distCalc := cvss.NewDistanceCalculator(vector1, vector2)

// Euclidean distance
euclidean := distCalc.EuclideanDistance()

// Manhattan distance
manhattan := distCalc.ManhattanDistance()

fmt.Printf("Euclidean distance: %.3f\n", euclidean)
fmt.Printf("Manhattan distance: %.3f\n", manhattan)
```

## Main Features

### 🧮 Score Calculation

- **Base score**: CVSS base score from base metrics
- **Temporal score**: Score adjustment accounting for temporal factors
- **Environmental score**: Final score based on environmental factors

### 📊 Vector Analysis

- **Distance calculation**: Distance between two vectors
- **Similarity analysis**: Assess how similar two vectors are
- **Vector comparison**: Multi-dimensional vector comparison

### 🔧 Data Handling

- **JSON serialization**: Full JSON support
- **Vector validation**: Ensure vectors are valid
- **Error handling**: Detailed error information

## Package Structure

```
cvss/
├── calculator.go          # Score calculator
├── cvss3x.go             # CVSS 3.x data structure
├── distance.go           # Distance calculator
├── json.go               # JSON support
├── errors.go             # Error definitions
└── utils.go              # Utility functions
```

## Type Definitions

### Calculator

`Calculator` is a struct (not an interface), constructed with the `*Cvss3x` to be scored:

```go
type Calculator struct { /* unexported: holds *Cvss3x */ }

func NewCalculator(cvss *Cvss3x) *Calculator
func (c *Calculator) Calculate() (float64, error)
func (c *Calculator) GetBaseScore() (float64, error)
func (c *Calculator) GetTemporalScore() (float64, error)
func (c *Calculator) GetEnvironmentalScore() (float64, error)
func (c *Calculator) GetSeverityRating(score float64) Severity // Severity is a named string type
```

### DistanceCalculator

`DistanceCalculator` is likewise a struct (not an interface), holding two `*Cvss3x`:

```go
func NewDistanceCalculator(vector1, vector2 *Cvss3x) *DistanceCalculator
func (dc *DistanceCalculator) EuclideanDistance() float64
func (dc *DistanceCalculator) ManhattanDistance() float64
func (dc *DistanceCalculator) HammingDistance() int
func (dc *DistanceCalculator) JaccardSimilarity() float64
func (dc *DistanceCalculator) ScoreDifference() float64
```

## Common Patterns

### 1. Basic Usage Pattern

```go
// Parse -> Calculate -> Output
vector, err := parser.ParseString(vectorString)
if err != nil {
    return err
}

calculator := cvss.NewCalculator(vector)
score, err := calculator.Calculate()
if err != nil {
    return err
}

fmt.Printf("Score: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
```

### 2. Batch Processing Pattern

```go
func processBatch(vectors []string) []Result {
    var results []Result

    for _, vectorStr := range vectors {
        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            continue
        }

        results = append(results, Result{
            Vector:   vectorStr,
            Score:    score,
            Severity: calculator.GetSeverityRating(score),
        })
    }

    return results
}
```

### 3. Vector Comparison Pattern

```go
func compareVectors(v1, v2 string) ComparisonResult {
    vector1, _ := parser.ParseString(v1)
    vector2, _ := parser.ParseString(v2)

    calc1 := cvss.NewCalculator(vector1)
    calc2 := cvss.NewCalculator(vector2)

    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()

    distCalc := cvss.NewDistanceCalculator(vector1, vector2)
    distance := distCalc.EuclideanDistance()

    return ComparisonResult{
        Score1:      score1,
        Score2:      score2,
        Distance:    distance,
        MoreSevere:  score1 > score2,
    }
}
```

## Performance Characteristics

### ⚡ High Performance

- **Zero-allocation calculation**: Optimized algorithms reduce memory allocation
- **Concurrency safe**: All calculators are concurrency-safe
- **Cache friendly**: Data structures designed with cache efficiency in mind

### 📈 Scalability

- **Plugin architecture**: Supports custom calculators
- **Interface design**: Easy to extend and test
- **Modular**: Functionality is modular, use as needed

## Best Practices

### 1. Error Handling

```go
calculator := cvss.NewCalculator(vector)
score, err := calculator.Calculate()
if err != nil {
    // Calculate returns a plain error via Check() (the first missing/invalid metric)
    log.Printf("Calculation failed (vector incomplete): %v", err)
    return
}
```

### 2. Resource Management

`Calculator` binds its vector at construction and has no `SetVector` method, so it **cannot** be reused via an object pool. Construct a fresh `Calculator` for each scoring (the cost is tiny); for batch scoring, just loop and construct:

```go
func calculateScore(vector *cvss.Cvss3x) (float64, error) {
    calc := cvss.NewCalculator(vector)
    return calc.Calculate()
}
```

### 3. Performance Monitoring

```go
func calculateWithMetrics(vector *cvss.Cvss3x) (float64, error) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        metrics.RecordCalculationTime(duration)
    }()

    calculator := cvss.NewCalculator(vector)
    return calculator.Calculate()
}
```

## Related Documentation

- [Calculator](/api/cvss/calculator) - Detailed calculator documentation
- [Cvss3x Data Structure](/api/cvss/cvss3x) - Understanding the data structure
- [DistanceCalculator](/api/cvss/distance) - Vector distance calculation
- [JSON Support](/api/cvss/json) - Serialization
- [Usage Examples](/examples/) - Practical examples
