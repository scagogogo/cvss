# DistanceCalculator - Vector Distance Calculator

The `DistanceCalculator` is used to calculate the distance between two CVSS vectors. It supports multiple distance algorithms and can be used for vector similarity analysis and clustering.

## How Distances Are Computed

Both vectors are projected into a numeric feature space (each metric → its score weight), then a chosen metric collapses the two feature vectors into a single number:

```mermaid
flowchart LR
    V1["Vector A"] --> F1["feature vector<br/>[AV, AC, PR, …]"]
    V2["Vector B"] --> F2["feature vector<br/>[AV, AC, PR, …]"]
    F1 --> M{metric}
    F2 --> M
    M --> E["Euclidean<br/>√Σ(aᵢ−bᵢ)²"]
    M --> Man["Manhattan<br/>Σ|aᵢ−bᵢ|"]
    M --> Ch["Chebyshev<br/>max|aᵢ−bᵢ|"]
    M --> Cos["Cosine<br/>A·B / |A||B|"]
    M --> Jac["Jaccard<br/>|A∩B| / |A∪B|"]

    classDef dist fill:#f9f0ff,stroke:#722ed1,color:#391085;
    class E,Man,Ch,Cos,Jac dist;
```

::: tip Distance vs similarity
Euclidean / Manhattan / Chebyshev return **distances** (0 = identical, larger = more different). Cosine / Jaccard return **similarities** (1 = identical, 0 = disjoint). Pick per use case: clustering favors distances, deduplication favors similarities.
:::

## Interface Definition

```go
type DistanceCalculator interface {
    EuclideanDistance() float64
    ManhattanDistance() float64
    ChebyshevDistance() float64
    CosineSimilarity() float64
    JaccardSimilarity() float64
}
```

## Creating Calculator

### NewDistanceCalculator

```go
func NewDistanceCalculator(vector1, vector2 *Cvss3x) DistanceCalculator
```

Creates a new distance calculator for two CVSS vectors.

**Parameters:**
- `vector1`: First CVSS vector
- `vector2`: Second CVSS vector

**Returns:**
- `DistanceCalculator`: Distance calculator instance

**Example:**
```go
calc := cvss.NewDistanceCalculator(vector1, vector2)
```

## Distance Algorithms

### EuclideanDistance

```go
func (d *DistanceCalculator) EuclideanDistance() float64
```

Calculates the Euclidean distance between two vectors.

**Formula:**
```
distance = √(Σ(xi - yi)²)
```

**Returns:**
- `float64`: Euclidean distance (0.0 to ~3.0)

**Example:**
```go
distance := calc.EuclideanDistance()
fmt.Printf("Euclidean distance: %.3f\n", distance)
```

**Use Cases:**
- General similarity measurement
- Clustering analysis
- Vector classification

### ManhattanDistance

```go
func (d *DistanceCalculator) ManhattanDistance() float64
```

Calculates the Manhattan (L1) distance between two vectors.

**Formula:**
```
distance = Σ|xi - yi|
```

**Returns:**
- `float64`: Manhattan distance

**Example:**
```go
distance := calc.ManhattanDistance()
fmt.Printf("Manhattan distance: %.3f\n", distance)
```

**Use Cases:**
- Robust to outliers
- Grid-based analysis
- Feature importance analysis

### ChebyshevDistance

```go
func (d *DistanceCalculator) ChebyshevDistance() float64
```

Calculates the Chebyshev (L∞) distance between two vectors.

**Formula:**
```
distance = max(|xi - yi|)
```

**Returns:**
- `float64`: Chebyshev distance

**Example:**
```go
distance := calc.ChebyshevDistance()
fmt.Printf("Chebyshev distance: %.3f\n", distance)
```

**Use Cases:**
- Maximum difference analysis
- Worst-case scenario comparison
- Uniform metric importance

### CosineSimilarity

```go
func (d *DistanceCalculator) CosineSimilarity() float64
```

Calculates the cosine similarity between two vectors.

**Formula:**
```
similarity = (A·B) / (||A|| × ||B||)
```

**Returns:**
- `float64`: Cosine similarity (-1.0 to 1.0)

**Example:**
```go
similarity := calc.CosineSimilarity()
fmt.Printf("Cosine similarity: %.3f\n", similarity)
```

**Use Cases:**
- Direction-based similarity
- Magnitude-independent comparison
- Text-like vector analysis

### JaccardSimilarity

```go
func (d *DistanceCalculator) JaccardSimilarity() float64
```

Calculates the Jaccard similarity between two vectors.

**Formula:**
```
similarity = |A ∩ B| / |A ∪ B|
```

**Returns:**
- `float64`: Jaccard similarity (0.0 to 1.0)

**Example:**
```go
similarity := calc.JaccardSimilarity()
fmt.Printf("Jaccard similarity: %.3f\n", similarity)
```

**Use Cases:**
- Set-based comparison
- Binary feature analysis
- Overlap measurement

## Complete Examples

### Basic Distance Calculation

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Parse two vectors
    parser1 := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    vector1, err := parser1.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    parser2 := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")
    vector2, err := parser2.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    // Create distance calculator
    calc := cvss.NewDistanceCalculator(vector1, vector2)
    
    // Calculate different distances
    fmt.Printf("Vector 1: %s\n", vector1.String())
    fmt.Printf("Vector 2: %s\n", vector2.String())
    fmt.Printf("\nDistance Metrics:\n")
    fmt.Printf("  Euclidean: %.3f\n", calc.EuclideanDistance())
    fmt.Printf("  Manhattan: %.3f\n", calc.ManhattanDistance())
    fmt.Printf("  Chebyshev: %.3f\n", calc.ChebyshevDistance())
    fmt.Printf("\nSimilarity Metrics:\n")
    fmt.Printf("  Cosine: %.3f\n", calc.CosineSimilarity())
    fmt.Printf("  Jaccard: %.3f\n", calc.JaccardSimilarity())
}
```

### Vector Clustering

```go
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

// Usage
vectors := []*cvss.Cvss3x{vector1, vector2, vector3, vector4}
clusters := clusterVectors(vectors, 0.5)

for i, cluster := range clusters {
    fmt.Printf("Cluster %d: %v\n", i+1, cluster)
}
```

### Similarity Matrix

```go
func calculateSimilarityMatrix(vectors []*cvss.Cvss3x) [][]float64 {
    n := len(vectors)
    matrix := make([][]float64, n)
    
    for i := range matrix {
        matrix[i] = make([]float64, n)
    }
    
    for i := 0; i < n; i++ {
        for j := 0; j < n; j++ {
            if i == j {
                matrix[i][j] = 1.0 // Perfect similarity with itself
            } else {
                calc := cvss.NewDistanceCalculator(vectors[i], vectors[j])
                matrix[i][j] = calc.CosineSimilarity()
            }
        }
    }
    
    return matrix
}

// Usage
matrix := calculateSimilarityMatrix(vectors)

fmt.Println("Similarity Matrix:")
for i, row := range matrix {
    fmt.Printf("Vector %d: ", i+1)
    for _, sim := range row {
        fmt.Printf("%.3f ", sim)
    }
    fmt.Println()
}
```

### Nearest Neighbor Search

```go
func findNearestNeighbors(target *cvss.Cvss3x, candidates []*cvss.Cvss3x, k int) []struct {
    Index    int
    Vector   *cvss.Cvss3x
    Distance float64
} {
    type neighbor struct {
        Index    int
        Vector   *cvss.Cvss3x
        Distance float64
    }
    
    var neighbors []neighbor
    
    for i, candidate := range candidates {
        calc := cvss.NewDistanceCalculator(target, candidate)
        distance := calc.EuclideanDistance()
        
        neighbors = append(neighbors, neighbor{
            Index:    i,
            Vector:   candidate,
            Distance: distance,
        })
    }
    
    // Sort by distance
    sort.Slice(neighbors, func(i, j int) bool {
        return neighbors[i].Distance < neighbors[j].Distance
    })
    
    // Return top k neighbors
    if k > len(neighbors) {
        k = len(neighbors)
    }
    
    return neighbors[:k]
}

// Usage
neighbors := findNearestNeighbors(targetVector, candidateVectors, 3)

fmt.Printf("Top 3 nearest neighbors to %s:\n", targetVector.String())
for i, neighbor := range neighbors {
    fmt.Printf("%d. %s (distance: %.3f)\n", 
        i+1, neighbor.Vector.String(), neighbor.Distance)
}
```

### Anomaly Detection

```go
func detectAnomalies(vectors []*cvss.Cvss3x, threshold float64) []int {
    var anomalies []int
    
    for i, vector1 := range vectors {
        var totalDistance float64
        var count int
        
        for j, vector2 := range vectors {
            if i == j {
                continue
            }
            
            calc := cvss.NewDistanceCalculator(vector1, vector2)
            totalDistance += calc.EuclideanDistance()
            count++
        }
        
        avgDistance := totalDistance / float64(count)
        
        if avgDistance > threshold {
            anomalies = append(anomalies, i)
        }
    }
    
    return anomalies
}

// Usage
anomalies := detectAnomalies(vectors, 2.0)

fmt.Printf("Detected %d anomalies:\n", len(anomalies))
for _, idx := range anomalies {
    fmt.Printf("  Vector %d: %s\n", idx+1, vectors[idx].String())
}
```

## Distance Interpretation

### Distance Ranges

| Distance Type | Range | Interpretation |
|---------------|-------|----------------|
| Euclidean | 0.0 - ~3.0 | 0.0 = identical, >2.0 = very different |
| Manhattan | 0.0 - ~8.0 | 0.0 = identical, >6.0 = very different |
| Chebyshev | 0.0 - 1.0 | 0.0 = identical, 1.0 = maximum difference |
| Cosine Similarity | -1.0 - 1.0 | 1.0 = identical direction, -1.0 = opposite |
| Jaccard Similarity | 0.0 - 1.0 | 1.0 = identical sets, 0.0 = no overlap |

### Similarity Thresholds

```go
func interpretSimilarity(distance float64, algorithm string) string {
    switch algorithm {
    case "euclidean":
        if distance < 0.5 {
            return "Very Similar"
        } else if distance < 1.0 {
            return "Similar"
        } else if distance < 2.0 {
            return "Somewhat Different"
        } else {
            return "Very Different"
        }
    case "cosine":
        if distance > 0.9 {
            return "Very Similar"
        } else if distance > 0.7 {
            return "Similar"
        } else if distance > 0.3 {
            return "Somewhat Different"
        } else {
            return "Very Different"
        }
    default:
        return "Unknown"
    }
}
```

## Performance Optimization

### Batch Calculation

```go
type BatchDistanceCalculator struct {
    vectors []*cvss.Cvss3x
    cache   map[string]float64
}

func NewBatchDistanceCalculator(vectors []*cvss.Cvss3x) *BatchDistanceCalculator {
    return &BatchDistanceCalculator{
        vectors: vectors,
        cache:   make(map[string]float64),
    }
}

func (b *BatchDistanceCalculator) GetDistance(i, j int, algorithm string) float64 {
    if i == j {
        return 0.0
    }
    
    // Ensure consistent ordering for cache key
    if i > j {
        i, j = j, i
    }
    
    key := fmt.Sprintf("%d-%d-%s", i, j, algorithm)
    
    if distance, exists := b.cache[key]; exists {
        return distance
    }
    
    calc := cvss.NewDistanceCalculator(b.vectors[i], b.vectors[j])
    
    var distance float64
    switch algorithm {
    case "euclidean":
        distance = calc.EuclideanDistance()
    case "manhattan":
        distance = calc.ManhattanDistance()
    case "cosine":
        distance = calc.CosineSimilarity()
    default:
        distance = calc.EuclideanDistance()
    }
    
    b.cache[key] = distance
    return distance
}
```

### Parallel Calculation

```go
func calculateDistanceMatrixParallel(vectors []*cvss.Cvss3x) [][]float64 {
    n := len(vectors)
    matrix := make([][]float64, n)
    
    for i := range matrix {
        matrix[i] = make([]float64, n)
    }
    
    var wg sync.WaitGroup
    
    for i := 0; i < n; i++ {
        for j := i; j < n; j++ {
            wg.Add(1)
            go func(row, col int) {
                defer wg.Done()
                
                if row == col {
                    matrix[row][col] = 0.0
                } else {
                    calc := cvss.NewDistanceCalculator(vectors[row], vectors[col])
                    distance := calc.EuclideanDistance()
                    matrix[row][col] = distance
                    matrix[col][row] = distance // Symmetric matrix
                }
            }(i, j)
        }
    }
    
    wg.Wait()
    return matrix
}
```

## Best Practices

### 1. Algorithm Selection

```go
func selectBestAlgorithm(useCase string) string {
    switch useCase {
    case "clustering":
        return "euclidean"
    case "similarity":
        return "cosine"
    case "anomaly_detection":
        return "manhattan"
    case "classification":
        return "euclidean"
    default:
        return "euclidean"
    }
}
```

### 2. Normalization

```go
func normalizeDistance(distance, maxDistance float64) float64 {
    if maxDistance == 0 {
        return 0
    }
    return distance / maxDistance
}
```

### 3. Error Handling

```go
func safeCalculateDistance(v1, v2 *cvss.Cvss3x) (float64, error) {
    if v1 == nil || v2 == nil {
        return 0, fmt.Errorf("vectors cannot be nil")
    }
    
    if !v1.IsValid() || !v2.IsValid() {
        return 0, fmt.Errorf("vectors must be valid")
    }
    
    calc := cvss.NewDistanceCalculator(v1, v2)
    return calc.EuclideanDistance(), nil
}
```

## Related Documentation

- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Calculator](/api/cvss/calculator)
- [Usage Examples](/examples/distance)
- [Clustering Examples](/examples/production)
