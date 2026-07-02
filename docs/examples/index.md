# Examples

This section provides a comprehensive collection of CVSS Skills examples, covering various use cases from basic usage to advanced functionality.

## Examples Overview

### 🚀 Getting Started Examples
- [Basic Usage](/examples/basic) - Simplest parsing and calculation examples
- [Vector Parsing](/examples/parsing) - Parsing vectors in various formats

### 📊 Feature Examples
- [JSON Output](/examples/json) - JSON serialization and deserialization
- [Temporal Metrics](/examples/temporal) - Using and impact of temporal metrics
- [Environmental Metrics](/examples/environmental) - Configuration and calculation of environmental metrics

### 🔍 Analysis Examples
- [Distance Calculation](/examples/distance) - Vector distance and similarity analysis
- [Vector Comparison](/examples/comparison) - Multiple comparison methods
- [Severity Levels](/examples/severity) - Severity rating and classification

### 🛠️ Advanced Examples
- [Edge Cases](/examples/edge-cases) - Error handling and edge cases

## Quick Start

If you're new to CVSS Skills, we recommend learning in the following order:

1. **[Basic Usage](/examples/basic)** - Understand basic parsing and calculation workflow
2. **[Vector Parsing](/examples/parsing)** - Learn how to parse vectors in different formats
3. **[JSON Output](/examples/json)** - Master data serialization and storage
4. **[Distance Calculation](/examples/distance)** - Explore vector analysis capabilities
5. **[Advanced Examples](/examples/edge-cases)** - Handle complex scenarios

## Example Categories

### Basic Operations

#### Vector Parsing
```go
// Parse a basic CVSS vector
vector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatal(err)
}
```

#### Score Calculation
```go
// Calculate CVSS score
calculator := cvss.NewCalculator(vector)
score, err := calculator.Calculate()
if err != nil {
    log.Fatal(err)
}

severity := calculator.GetSeverityRating(score)
fmt.Printf("Score: %.1f (%s)\n", score, severity)
```

### Data Processing

#### JSON Serialization
```go
// Convert to JSON
jsonData, err := json.MarshalIndent(vector, "", "  ")
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

#### Batch Processing
```go
// Process multiple vectors
vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
}

for _, vectorStr := range vectors {
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        fmt.Printf("Error parsing %s: %v\n", vectorStr, err)
        continue
    }
    
    calculator := cvss.NewCalculator(vector)
    score, _ := calculator.Calculate()
    severity := calculator.GetSeverityRating(score)
    
    fmt.Printf("%s -> %.1f (%s)\n", vectorStr, score, severity)
}
```

### Advanced Analysis

#### Vector Distance Calculation
```go
// Calculate distance between vectors
calc := cvss.NewDistanceCalculator(vector1, vector2)
distance := calc.EuclideanDistance()
similarity := calc.JaccardSimilarity()

fmt.Printf("Distance: %.3f\n", distance)
fmt.Printf("Similarity: %.3f\n", similarity)
```

#### Vector Clustering
```go
// Group similar vectors
func clusterVectors(vectors []*cvss.Cvss3x, threshold float64) [][]int {
    var clusters [][]int
    used := make([]bool, len(vectors))
    
    for i, vector1 := range vectors {
        if used[i] {
            continue
        }
        
        cluster := []int{i}
        used[i] = true
        
        for j, vector2 := range vectors {
            if i == j || used[j] {
                continue
            }
            
            calc := cvss.NewDistanceCalculator(vector1, vector2)
            distance := calc.EuclideanDistance()
            
            if distance <= threshold {
                cluster = append(cluster, j)
                used[j] = true
            }
        }
        
        clusters = append(clusters, cluster)
    }
    
    return clusters
}
```

## Error Handling Examples

### Robust Parsing
```go
func safeParseVector(vectorStr string) (*cvss.Cvss3x, error) {
    // Input validation
    if vectorStr == "" {
        return nil, fmt.Errorf("vector string cannot be empty")
    }
    
    if !strings.HasPrefix(vectorStr, "CVSS:") {
        return nil, fmt.Errorf("invalid vector format")
    }
    
    // Parse with error handling
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        return nil, fmt.Errorf("parse failed: %w", err)
    }

    // Validation (Check returns the first missing/invalid metric)
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("parsed vector is invalid: %w", err)
    }
    
    return vector, nil
}
```

### Error Recovery
```go
func parseWithFallback(vectorStr string) (*cvss.Cvss3x, error) {
    // Try strict parsing first (ParseString enforces the CVSS: prefix
    // and rejects unknown metrics/values)
    vector, err := parser.ParseString(vectorStr)
    if err == nil {
        return vector, nil
    }

    // Fall back to relaxed parsing: accepts inputs without the CVSS:3.x/
    // prefix and fills in the requested default version
    return parser.ParseRelaxed(vectorStr, "3.1")
}
```

## Performance Examples

### Concurrent Processing
```go
func processVectorsConcurrently(vectors []string) []Result {
    results := make([]Result, len(vectors))
    var wg sync.WaitGroup
    
    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, vector string) {
            defer wg.Done()
            
            cvssVector, err := parser.ParseString(vector)
            if err != nil {
                results[index] = Result{Error: err}
                return
            }

            calculator := cvss.NewCalculator(cvssVector)
            score, err := calculator.Calculate()
            if err != nil {
                results[index] = Result{Error: err}
                return
            }

            results[index] = Result{
                Vector:   cvssVector,
                Score:    score,
                Severity: calculator.GetSeverityRating(score).String(),
            }
        }(i, vectorStr)
    }
    
    wg.Wait()
    return results
}

type Result struct {
    Vector   *cvss.Cvss3x
    Score    float64
    Severity string
    Error    error
}
```

### Memory Optimization
```go
// Cvss3xParser binds its input string at construction and cannot be
// rebound, so an object pool gains nothing. Just call ParseString per
// input — each call constructs a fresh, cheap parser.
func parsePerCall(vectorStr string) (*cvss.Cvss3x, error) {
    return parser.ParseString(vectorStr)
}
```

## Integration Examples

### HTTP API
```go
func handleCVSSAnalysis(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Vectors []string `json:"vectors"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    var results []map[string]interface{}
    
    for _, vectorStr := range request.Vectors {
        result := map[string]interface{}{
            "vector": vectorStr,
        }
        
        vector, err := safeParseVector(vectorStr)
        if err != nil {
            result["error"] = err.Error()
            results = append(results, result)
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()
        
        result["score"] = score
        result["severity"] = calculator.GetSeverityRating(score)
        result["parsed"] = vector
        
        results = append(results, result)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "results": results,
    })
}
```

### Database Storage
```go
func saveVectorToDB(db *sql.DB, vectorStr string) error {
    vector, err := safeParseVector(vectorStr)
    if err != nil {
        return err
    }
    
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        return err
    }
    
    jsonData, err := json.Marshal(vector)
    if err != nil {
        return err
    }
    
    query := `
        INSERT INTO cvss_vectors (vector_string, score, severity, json_data, created_at) 
        VALUES (?, ?, ?, ?, ?)
    `
    
    _, err = db.Exec(query, 
        vectorStr, 
        score, 
        calculator.GetSeverityRating(score),
        string(jsonData), 
        time.Now(),
    )
    
    return err
}
```

## Testing Examples

### Unit Testing
```go
func TestVectorParsing(t *testing.T) {
    testCases := []struct {
        name     string
        vector   string
        expected float64
        hasError bool
    }{
        {
            name:     "High severity vector",
            vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expected: 9.8,
            hasError: false,
        },
        {
            name:     "Low severity vector",
            vector:   "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            expected: 2.9,
            hasError: false,
        },
        {
            name:     "Invalid vector",
            vector:   "INVALID",
            expected: 0,
            hasError: true,
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            vector, err := safeParseVector(tc.vector)
            
            if tc.hasError {
                assert.Error(t, err)
                return
            }
            
            assert.NoError(t, err)
            assert.NotNil(t, vector)
            
            calculator := cvss.NewCalculator(vector)
            score, err := calculator.Calculate()
            assert.NoError(t, err)
            assert.InDelta(t, tc.expected, score, 0.1)
        })
    }
}
```

## Next Steps

After exploring these examples, you can:

1. **Read the [API Documentation](/api/)** for detailed interface specifications
2. **Check the [GitHub Repository](https://github.com/scagogogo/cvss-skills)** for the latest updates
3. **Contribute** by submitting issues or pull requests
4. **Join the Community** for discussions and support

## Getting Help

If you need help with any of these examples:

- Check the [API Documentation](/api/) for detailed method descriptions
- Browse the [GitHub Issues](https://github.com/scagogogo/cvss-skills/issues) for common problems
- Submit a new issue if you find a bug or need a feature
- Join our [Community Discussions](https://github.com/scagogogo/cvss-skills/discussions) for general questions
