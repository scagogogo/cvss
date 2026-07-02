# Distance Calculation Examples

This example demonstrates how to calculate distances between CVSS vectors for similarity analysis, clustering, and comparative security assessment.

## Overview

Distance calculation allows you to:

- Compare similarity between vulnerabilities
- Cluster similar security issues
- Identify outliers and anomalies
- Track vulnerability evolution over time
- Prioritize remediation efforts

## Basic Distance Calculation

### Simple Distance Comparison

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Parse two CVSS vectors
    vector1Str := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vector2Str := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

    parser1 := parser.NewCvss3xParser(vector1Str)
    vector1, err := parser1.Parse()
    if err != nil {
        log.Fatal(err)
    }

    parser2 := parser.NewCvss3xParser(vector2Str)
    vector2, err := parser2.Parse()
    if err != nil {
        log.Fatal(err)
    }

    // Create distance calculator
    calc := cvss.NewDistanceCalculator(vector1, vector2)

    // Calculate different distance metrics
    fmt.Printf("Vector 1: %s\n", vector1.String())
    fmt.Printf("Vector 2: %s\n", vector2.String())
    fmt.Printf("\nDistance Metrics:\n")
    fmt.Printf("  Euclidean Distance: %.3f\n", calc.EuclideanDistance())
    fmt.Printf("  Manhattan Distance: %.3f\n", calc.ManhattanDistance())
    fmt.Printf("  Chebyshev Distance: %.3f\n", calc.ChebyshevDistance())
    fmt.Printf("\nSimilarity Metrics:\n")
    fmt.Printf("  Cosine Similarity: %.3f\n", calc.CosineSimilarity())
    fmt.Printf("  Jaccard Similarity: %.3f\n", calc.JaccardSimilarity())
}
```

### Distance Interpretation

```go
func interpretDistance(distance float64, algorithm string) string {
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

func analyzeVectorSimilarity(v1, v2 *cvss.Cvss3x) {
    calc := cvss.NewDistanceCalculator(v1, v2)
    
    euclidean := calc.EuclideanDistance()
    cosine := calc.CosineSimilarity()
    
    fmt.Printf("Similarity Analysis:\n")
    fmt.Printf("  Vector 1: %s\n", v1.String())
    fmt.Printf("  Vector 2: %s\n", v2.String())
    fmt.Printf("  Euclidean: %.3f (%s)\n", euclidean, interpretDistance(euclidean, "euclidean"))
    fmt.Printf("  Cosine: %.3f (%s)\n", cosine, interpretDistance(cosine, "cosine"))
}
```

## Distance Algorithms

### Euclidean Distance

```go
func demonstrateEuclideanDistance() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Critical
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // High
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // Low
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            log.Fatal(err)
        }
        parsedVectors[i] = vector
    }

    fmt.Println("Euclidean Distance Matrix:")
    fmt.Printf("%10s", "")
    for i := range parsedVectors {
        fmt.Printf("%10s", fmt.Sprintf("V%d", i+1))
    }
    fmt.Println()

    for i, v1 := range parsedVectors {
        fmt.Printf("%10s", fmt.Sprintf("V%d", i+1))
        for _, v2 := range parsedVectors {
            if v1 == v2 {
                fmt.Printf("%10s", "0.000")
            } else {
                calc := cvss.NewDistanceCalculator(v1, v2)
                distance := calc.EuclideanDistance()
                fmt.Printf("%10.3f", distance)
            }
        }
        fmt.Println()
    }
}
```

### Manhattan Distance

```go
func demonstrateManhattanDistance() {
    // Manhattan distance is useful for understanding
    // the total difference across all metrics
    
    vector1Str := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vector2Str := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

    parser1 := parser.NewCvss3xParser(vector1Str)
    vector1, _ := parser1.Parse()

    parser2 := parser.NewCvss3xParser(vector2Str)
    vector2, _ := parser2.Parse()

    calc := cvss.NewDistanceCalculator(vector1, vector2)
    manhattan := calc.ManhattanDistance()

    fmt.Printf("Manhattan Distance Analysis:\n")
    fmt.Printf("Vector 1: %s\n", vector1.String())
    fmt.Printf("Vector 2: %s\n", vector2.String())
    fmt.Printf("Manhattan Distance: %.3f\n", manhattan)
    fmt.Printf("Interpretation: %s\n", interpretManhattanDistance(manhattan))
}

func interpretManhattanDistance(distance float64) string {
    if distance < 1.0 {
        return "Very similar vectors"
    } else if distance < 3.0 {
        return "Moderately similar vectors"
    } else if distance < 5.0 {
        return "Somewhat different vectors"
    } else {
        return "Very different vectors"
    }
}
```

### Cosine Similarity

```go
func demonstrateCosineSimilarity() {
    // Cosine similarity is useful for understanding
    // directional similarity regardless of magnitude
    
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // Similar pattern, lower availability
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // Different pattern
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    fmt.Println("Cosine Similarity Analysis:")
    for i := 0; i < len(parsedVectors); i++ {
        for j := i + 1; j < len(parsedVectors); j++ {
            calc := cvss.NewDistanceCalculator(parsedVectors[i], parsedVectors[j])
            similarity := calc.CosineSimilarity()
            
            fmt.Printf("V%d vs V%d: %.3f (%s)\n", 
                i+1, j+1, similarity, interpretCosineSimilarity(similarity))
        }
    }
}

func interpretCosineSimilarity(similarity float64) string {
    if similarity > 0.95 {
        return "Nearly identical patterns"
    } else if similarity > 0.8 {
        return "Very similar patterns"
    } else if similarity > 0.6 {
        return "Moderately similar patterns"
    } else if similarity > 0.3 {
        return "Somewhat similar patterns"
    } else {
        return "Different patterns"
    }
}
```

## Vector Clustering

### K-Means Style Clustering

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

func demonstrateClustering() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Critical network
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // Critical network (similar)
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Critical local
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // Critical local (similar)
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // Low severity
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", // Low severity (similar)
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    clusters := clusterVectors(parsedVectors, 0.5)

    fmt.Printf("Clustering Results (threshold: 0.5):\n")
    for i, cluster := range clusters {
        fmt.Printf("Cluster %d (%d vectors):\n", i+1, len(cluster))
        for _, idx := range cluster {
            fmt.Printf("  [%d] %s\n", idx, vectors[idx])
        }
        fmt.Println()
    }
}
```

### Hierarchical Clustering

```go
func hierarchicalClustering(vectors []*cvss.Cvss3x) {
    n := len(vectors)
    
    // Calculate distance matrix
    distances := make([][]float64, n)
    for i := range distances {
        distances[i] = make([]float64, n)
    }

    for i := 0; i < n; i++ {
        for j := 0; j < n; j++ {
            if i == j {
                distances[i][j] = 0
            } else {
                calc := cvss.NewDistanceCalculator(vectors[i], vectors[j])
                distances[i][j] = calc.EuclideanDistance()
            }
        }
    }

    // Simple hierarchical clustering (single linkage)
    clusters := make([][]int, n)
    for i := range clusters {
        clusters[i] = []int{i}
    }

    fmt.Println("Hierarchical Clustering Steps:")
    step := 1

    for len(clusters) > 1 {
        minDist := math.Inf(1)
        var mergeI, mergeJ int

        // Find closest clusters
        for i := 0; i < len(clusters); i++ {
            for j := i + 1; j < len(clusters); j++ {
                dist := clusterDistance(clusters[i], clusters[j], distances)
                if dist < minDist {
                    minDist = dist
                    mergeI, mergeJ = i, j
                }
            }
        }

        fmt.Printf("Step %d: Merge clusters %v and %v (distance: %.3f)\n", 
            step, clusters[mergeI], clusters[mergeJ], minDist)

        // Merge clusters
        newCluster := append(clusters[mergeI], clusters[mergeJ]...)
        newClusters := [][]int{newCluster}

        for i, cluster := range clusters {
            if i != mergeI && i != mergeJ {
                newClusters = append(newClusters, cluster)
            }
        }

        clusters = newClusters
        step++
    }
}

func clusterDistance(cluster1, cluster2 []int, distances [][]float64) float64 {
    minDist := math.Inf(1)
    
    for _, i := range cluster1 {
        for _, j := range cluster2 {
            if distances[i][j] < minDist {
                minDist = distances[i][j]
            }
        }
    }
    
    return minDist
}
```

## Similarity Analysis

### Find Similar Vectors

```go
func findSimilarVectors(target *cvss.Cvss3x, candidates []*cvss.Cvss3x, threshold float64) []SimilarVector {
    var similar []SimilarVector

    for i, candidate := range candidates {
        calc := cvss.NewDistanceCalculator(target, candidate)
        distance := calc.EuclideanDistance()
        similarity := calc.CosineSimilarity()

        if distance <= threshold {
            similar = append(similar, SimilarVector{
                Index:      i,
                Vector:     candidate,
                Distance:   distance,
                Similarity: similarity,
            })
        }
    }

    // Sort by distance (most similar first)
    sort.Slice(similar, func(i, j int) bool {
        return similar[i].Distance < similar[j].Distance
    })

    return similar
}

type SimilarVector struct {
    Index      int
    Vector     *cvss.Cvss3x
    Distance   float64
    Similarity float64
}

func (sv SimilarVector) String() string {
    return fmt.Sprintf("[%d] %s (dist: %.3f, sim: %.3f)", 
        sv.Index, sv.Vector.String(), sv.Distance, sv.Similarity)
}
```

### Nearest Neighbors

```go
func findNearestNeighbors(target *cvss.Cvss3x, candidates []*cvss.Cvss3x, k int) []SimilarVector {
    var neighbors []SimilarVector

    for i, candidate := range candidates {
        calc := cvss.NewDistanceCalculator(target, candidate)
        distance := calc.EuclideanDistance()
        similarity := calc.CosineSimilarity()

        neighbors = append(neighbors, SimilarVector{
            Index:      i,
            Vector:     candidate,
            Distance:   distance,
            Similarity: similarity,
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

func demonstrateNearestNeighbors() {
    target := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    candidates := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // Very similar
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // Similar
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Somewhat similar
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // Different
    }

    // Parse target
    targetParser := parser.NewCvss3xParser(target)
    targetVector, _ := targetParser.Parse()

    // Parse candidates
    candidateVectors := make([]*cvss.Cvss3x, len(candidates))
    for i, candidateStr := range candidates {
        candidateParser := parser.NewCvss3xParser(candidateStr)
        vector, _ := candidateParser.Parse()
        candidateVectors[i] = vector
    }

    // Find nearest neighbors
    neighbors := findNearestNeighbors(targetVector, candidateVectors, 3)

    fmt.Printf("Target: %s\n", target)
    fmt.Printf("Top 3 nearest neighbors:\n")
    for i, neighbor := range neighbors {
        fmt.Printf("%d. %s\n", i+1, neighbor.String())
    }
}
```

## Anomaly Detection

### Statistical Outlier Detection

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

func demonstrateAnomalyDetection() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Normal high severity
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // Normal high severity
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // Normal high severity
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // Normal low severity
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", // Normal low severity
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H", // Anomaly: physical access with high availability impact
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    anomalies := detectAnomalies(parsedVectors, 2.0)

    fmt.Printf("Anomaly Detection Results (threshold: 2.0):\n")
    if len(anomalies) == 0 {
        fmt.Println("No anomalies detected")
    } else {
        fmt.Printf("Detected %d anomalies:\n", len(anomalies))
        for _, idx := range anomalies {
            fmt.Printf("  [%d] %s\n", idx, vectors[idx])
        }
    }
}
```

## Performance Optimization

### Batch Distance Calculation

```go
type BatchDistanceCalculator struct {
    vectors []*cvss.Cvss3x
    cache   map[string]float64
    mutex   sync.RWMutex
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

    b.mutex.RLock()
    if distance, exists := b.cache[key]; exists {
        b.mutex.RUnlock()
        return distance
    }
    b.mutex.RUnlock()

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

    b.mutex.Lock()
    b.cache[key] = distance
    b.mutex.Unlock()

    return distance
}
```

### Parallel Distance Matrix

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

## Practical Applications

### Vulnerability Prioritization

```go
func prioritizeVulnerabilities(vulnerabilities []*cvss.Cvss3x, criticalThreshold float64) []int {
    var priorities []int

    // Find critical vulnerabilities
    var criticalVulns []*cvss.Cvss3x
    for i, vuln := range vulnerabilities {
        calculator := cvss.NewCalculator(vuln)
        score, _ := calculator.Calculate()
        
        if score >= criticalThreshold {
            criticalVulns = append(criticalVulns, vuln)
            priorities = append(priorities, i)
        }
    }

    // Sort by similarity to most critical
    if len(criticalVulns) > 0 {
        mostCritical := criticalVulns[0]
        
        sort.Slice(priorities, func(i, j int) bool {
            calc1 := cvss.NewDistanceCalculator(mostCritical, vulnerabilities[priorities[i]])
            calc2 := cvss.NewDistanceCalculator(mostCritical, vulnerabilities[priorities[j]])
            
            return calc1.EuclideanDistance() < calc2.EuclideanDistance()
        })
    }

    return priorities
}
```

## Next Steps

After mastering distance calculations, you can explore:

- [Temporal Metrics](/examples/temporal) - Time-based analysis
- [Environmental Metrics](/examples/environmental) - Context-specific scoring
- [Advanced Examples](/examples/edge-cases) - Complex scenarios

## Related Documentation

- [Distance Calculator API](/api/cvss/distance) - Detailed API reference
- [Vector Comparison Guide](/examples/comparison) - Comparison techniques
- [Clustering Algorithms](/examples/production) - Advanced clustering methods
