# 距离计算示例

本示例演示如何计算 CVSS 向量之间的距离，用于相似性分析、聚类和比较安全评估。

## 概述

距离计算允许您：

- 比较漏洞之间的相似性
- 聚类相似的安全问题
- 识别异常值和异常情况
- 跟踪漏洞随时间的演变
- 优先处理修复工作

## 基本距离计算

### 简单距离比较

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 解析两个 CVSS 向量
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

    // 创建距离计算器
    calc := cvss.NewDistanceCalculator(vector1, vector2)

    // 计算不同的距离指标
    fmt.Printf("向量 1: %s\n", vector1.String())
    fmt.Printf("向量 2: %s\n", vector2.String())
    fmt.Printf("\n距离指标:\n")
    fmt.Printf("  欧几里得距离: %.3f\n", calc.EuclideanDistance())
    fmt.Printf("  曼哈顿距离: %.3f\n", calc.ManhattanDistance())
    fmt.Printf("  切比雪夫距离: %.3f\n", calc.ChebyshevDistance())
    fmt.Printf("\n相似性指标:\n")
    fmt.Printf("  余弦相似度: %.3f\n", calc.CosineSimilarity())
    fmt.Printf("  雅卡德相似度: %.3f\n", calc.JaccardSimilarity())
}
```

### 距离解释

```go
func interpretDistance(distance float64, algorithm string) string {
    switch algorithm {
    case "euclidean":
        if distance < 0.5 {
            return "非常相似"
        } else if distance < 1.0 {
            return "相似"
        } else if distance < 2.0 {
            return "有些不同"
        } else {
            return "非常不同"
        }
    case "cosine":
        if distance > 0.9 {
            return "非常相似"
        } else if distance > 0.7 {
            return "相似"
        } else if distance > 0.3 {
            return "有些相似"
        } else {
            return "非常不同"
        }
    default:
        return "未知"
    }
}

func analyzeVectorSimilarity(v1, v2 *cvss.Cvss3x) {
    calc := cvss.NewDistanceCalculator(v1, v2)
    
    euclidean := calc.EuclideanDistance()
    cosine := calc.CosineSimilarity()
    
    fmt.Printf("相似性分析:\n")
    fmt.Printf("  向量 1: %s\n", v1.String())
    fmt.Printf("  向量 2: %s\n", v2.String())
    fmt.Printf("  欧几里得: %.3f (%s)\n", euclidean, interpretDistance(euclidean, "euclidean"))
    fmt.Printf("  余弦: %.3f (%s)\n", cosine, interpretDistance(cosine, "cosine"))
}
```

## 距离算法

### 欧几里得距离

```go
func demonstrateEuclideanDistance() {
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 严重网络
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // 高网络
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // 低本地
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

    fmt.Println("欧几里得距离矩阵:")
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

### 曼哈顿距离

```go
func demonstrateManhattanDistance() {
    // 曼哈顿距离对于理解所有指标的总差异很有用
    
    vector1Str := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vector2Str := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

    parser1 := parser.NewCvss3xParser(vector1Str)
    vector1, _ := parser1.Parse()

    parser2 := parser.NewCvss3xParser(vector2Str)
    vector2, _ := parser2.Parse()

    calc := cvss.NewDistanceCalculator(vector1, vector2)
    manhattan := calc.ManhattanDistance()

    fmt.Printf("曼哈顿距离分析:\n")
    fmt.Printf("向量 1: %s\n", vector1.String())
    fmt.Printf("向量 2: %s\n", vector2.String())
    fmt.Printf("曼哈顿距离: %.3f\n", manhattan)
    fmt.Printf("解释: %s\n", interpretManhattanDistance(manhattan))
}

func interpretManhattanDistance(distance float64) string {
    if distance < 1.0 {
        return "非常相似的向量"
    } else if distance < 3.0 {
        return "中等相似的向量"
    } else if distance < 5.0 {
        return "有些不同的向量"
    } else {
        return "非常不同的向量"
    }
}
```

### 余弦相似度

```go
func demonstrateCosineSimilarity() {
    // 余弦相似度对于理解方向相似性很有用，不考虑大小
    
    vectors := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 相似模式，较低可用性
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // 不同模式
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    fmt.Println("余弦相似度分析:")
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
        return "几乎相同的模式"
    } else if similarity > 0.8 {
        return "非常相似的模式"
    } else if similarity > 0.6 {
        return "中等相似的模式"
    } else if similarity > 0.3 {
        return "有些相似的模式"
    } else {
        return "不同的模式"
    }
}
```

## 向量聚类

### K-Means 风格聚类

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
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 严重网络
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 严重网络（相似）
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 严重本地
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 严重本地（相似）
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // 低严重性
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", // 低严重性（相似）
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    clusters := clusterVectors(parsedVectors, 0.5)

    fmt.Printf("聚类结果（阈值: 0.5）:\n")
    for i, cluster := range clusters {
        fmt.Printf("聚类 %d (%d 个向量):\n", i+1, len(cluster))
        for _, idx := range cluster {
            fmt.Printf("  [%d] %s\n", idx, vectors[idx])
        }
        fmt.Println()
    }
}
```

## 相似性分析

### 查找相似向量

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

    // 按距离排序（最相似的在前）
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
    return fmt.Sprintf("[%d] %s (距离: %.3f, 相似度: %.3f)", 
        sv.Index, sv.Vector.String(), sv.Distance, sv.Similarity)
}
```

### 最近邻

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

    // 按距离排序
    sort.Slice(neighbors, func(i, j int) bool {
        return neighbors[i].Distance < neighbors[j].Distance
    })

    // 返回前 k 个邻居
    if k > len(neighbors) {
        k = len(neighbors)
    }

    return neighbors[:k]
}

func demonstrateNearestNeighbors() {
    target := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    candidates := []string{
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 非常相似
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // 相似
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 有些相似
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // 不同
    }

    // 解析目标
    targetParser := parser.NewCvss3xParser(target)
    targetVector, _ := targetParser.Parse()

    // 解析候选者
    candidateVectors := make([]*cvss.Cvss3x, len(candidates))
    for i, candidateStr := range candidates {
        candidateParser := parser.NewCvss3xParser(candidateStr)
        vector, _ := candidateParser.Parse()
        candidateVectors[i] = vector
    }

    // 查找最近邻
    neighbors := findNearestNeighbors(targetVector, candidateVectors, 3)

    fmt.Printf("目标: %s\n", target)
    fmt.Printf("前 3 个最近邻:\n")
    for i, neighbor := range neighbors {
        fmt.Printf("%d. %s\n", i+1, neighbor.String())
    }
}
```

## 异常检测

### 统计异常值检测

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
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 正常高严重性
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 正常高严重性
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // 正常高严重性
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", // 正常低严重性
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", // 正常低严重性
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H", // 异常：物理访问但高可用性影响
    }

    parsedVectors := make([]*cvss.Cvss3x, len(vectors))
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        parsedVectors[i] = vector
    }

    anomalies := detectAnomalies(parsedVectors, 2.0)

    fmt.Printf("异常检测结果（阈值: 2.0）:\n")
    if len(anomalies) == 0 {
        fmt.Println("未检测到异常")
    } else {
        fmt.Printf("检测到 %d 个异常:\n", len(anomalies))
        for _, idx := range anomalies {
            fmt.Printf("  [%d] %s\n", idx, vectors[idx])
        }
    }
}
```

## 性能优化

### 批量距离计算

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

    // 确保缓存键的一致顺序
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

## 实际应用

### 漏洞优先级排序

```go
func prioritizeVulnerabilities(vulnerabilities []*cvss.Cvss3x, criticalThreshold float64) []int {
    var priorities []int

    // 查找严重漏洞
    var criticalVulns []*cvss.Cvss3x
    for i, vuln := range vulnerabilities {
        calculator := cvss.NewCalculator(vuln)
        score, _ := calculator.Calculate()
        
        if score >= criticalThreshold {
            criticalVulns = append(criticalVulns, vuln)
            priorities = append(priorities, i)
        }
    }

    // 按与最严重漏洞的相似性排序
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

## 下一步

掌握距离计算后，您可以探索：

- [时间指标](/zh/examples/temporal) - 基于时间的分析
- [环境指标](/zh/examples/environmental) - 特定上下文评分
- [高级示例](/zh/examples/edge-cases) - 复杂场景

## 相关文档

- [距离计算器 API](/zh/api/cvss/distance) - 详细 API 参考
- [向量比较指南](/zh/examples/comparison) - 比较技术
- [聚类算法](/zh/examples/edge-cases) - 高级聚类方法
