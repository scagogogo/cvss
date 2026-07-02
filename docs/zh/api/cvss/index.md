# cvss 包

`cvss` 包是 CVSS Skills 的核心包，提供了 CVSS 3.x 向量的数据结构、评分计算和分析功能。

## 包概述

```go
import "github.com/scagogogo/cvss-skills/pkg/cvss"
```

## 主要类型

### 核心结构

| 类型 | 描述 | 文档链接 |
|------|------|----------|
| `Cvss3x` | CVSS 3.x 向量的主要数据结构 | [详细文档](/zh/api/cvss/cvss3x) |
| `Cvss3xBase` | 基础指标组 | [详细文档](/zh/api/cvss/cvss3x) |
| `Cvss3xTemporal` | 时间指标组 | [详细文档](/zh/api/cvss/cvss3x) |
| `Cvss3xEnvironmental` | 环境指标组 | [详细文档](/zh/api/cvss/cvss3x) |

### 计算器

| 类型 | 描述 | 文档链接 |
|------|------|----------|
| `Calculator` | CVSS 评分计算器 | [详细文档](/zh/api/cvss/calculator) |
| `DistanceCalculator` | 向量距离计算器 | [详细文档](/zh/api/cvss/distance) |

## 快速示例

### 创建 CVSS 向量

```go
// 手动创建向量
cvssVector := cvss.NewCvss3x()
cvssVector.MajorVersion = 3
cvssVector.MinorVersion = 1

// 设置基础指标
cvssVector.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
cvssVector.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
// ... 设置其他指标
```

### 计算评分

```go
// 创建计算器
calculator := cvss.NewCalculator(cvssVector)

// 计算基础评分
baseScore, err := calculator.GetBaseScore()
if err != nil {
    log.Fatal(err)
}

// 计算时间评分
temporalScore, err := calculator.GetTemporalScore()
if err != nil {
    log.Fatal(err)
}

// 计算环境评分
environmentalScore, err := calculator.GetEnvironmentalScore()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("基础评分: %.1f\n", baseScore)
fmt.Printf("时间评分: %.1f\n", temporalScore)
fmt.Printf("环境评分: %.1f\n", environmentalScore)
```

### 向量距离计算

```go
// 创建两个向量
vector1, _ := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").Parse()
vector2, _ := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L").Parse()

// 计算距离
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
euclideanDist := distCalc.EuclideanDistance()
manhattanDist := distCalc.ManhattanDistance()

fmt.Printf("欧几里得距离: %.3f\n", euclideanDist)
fmt.Printf("曼哈顿距离: %.3f\n", manhattanDist)
```

## 主要功能

### 🧮 评分计算

- **基础评分**: 根据基础指标计算 CVSS 基础评分
- **时间评分**: 考虑时间因素的评分调整
- **环境评分**: 根据环境因素的最终评分

### 📊 向量分析

- **距离计算**: 计算两个向量之间的距离
- **相似度分析**: 评估向量的相似程度
- **向量比较**: 多维度的向量对比

### 🔧 数据处理

- **JSON 序列化**: 完整的 JSON 支持
- **向量验证**: 确保向量的有效性
- **错误处理**: 详细的错误信息

## 包结构

```
cvss/
├── calculator.go          # 评分计算器
├── cvss3x.go             # CVSS 3.x 数据结构
├── distance.go           # 距离计算器
├── json.go               # JSON 支持
├── errors.go             # 错误定义
└── utils.go              # 工具函数
```

## 类型定义

### Calculator

`Calculator` 是一个结构体（非接口），用待评分的 `*Cvss3x` 构造：

```go
type Calculator struct { /* 非导出：持有 *Cvss3x */ }

func NewCalculator(cvss *Cvss3x) *Calculator
func (c *Calculator) Calculate() (float64, error)
func (c *Calculator) GetBaseScore() (float64, error)
func (c *Calculator) GetTemporalScore() (float64, error)
func (c *Calculator) GetEnvironmentalScore() (float64, error)
func (c *Calculator) GetSeverityRating(score float64) Severity // Severity 是命名字符串类型
```

### DistanceCalculator

`DistanceCalculator` 同样是结构体（非接口），持有两个 `*Cvss3x`：

```go
func NewDistanceCalculator(vector1, vector2 *Cvss3x) *DistanceCalculator
func (dc *DistanceCalculator) EuclideanDistance() float64
func (dc *DistanceCalculator) ManhattanDistance() float64
func (dc *DistanceCalculator) HammingDistance() int
func (dc *DistanceCalculator) JaccardSimilarity() float64
func (dc *DistanceCalculator) ScoreDifference() float64
```

## 常用模式

### 1. 基本使用模式

```go
// 解析 -> 计算 -> 输出
vector, err := parser.ParseString(vectorString)
if err != nil {
    return err
}

calculator := cvss.NewCalculator(vector)
score, err := calculator.Calculate()
if err != nil {
    return err
}

fmt.Printf("评分: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
```

### 2. 批量处理模式

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
            Vector: vectorStr,
            Score:  score,
            Severity: calculator.GetSeverityRating(score),
        })
    }
    
    return results
}
```

### 3. 向量比较模式

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
        Score1:   score1,
        Score2:   score2,
        Distance: distance,
        MoreSevere: score1 > score2,
    }
}
```

## 性能特性

### ⚡ 高性能

- **零分配计算**: 优化的计算算法，减少内存分配
- **并发安全**: 所有计算器都是并发安全的
- **缓存友好**: 数据结构设计考虑了缓存效率

### 📈 可扩展性

- **插件架构**: 支持自定义计算器
- **接口设计**: 易于扩展和测试
- **模块化**: 功能模块化，按需使用

## 最佳实践

### 1. 错误处理

```go
calculator := cvss.NewCalculator(vector)
score, err := calculator.Calculate()
if err != nil {
    // Calculate 通过 Check() 返回普通 error（首个缺失/无效指标）
    log.Printf("计算失败（向量不完整）: %v", err)
    return
}
```

### 2. 资源管理

`Calculator` 在构造时绑定向量，没有 `SetVector` 方法，因此**不可**用对象池复用。每次评分构造新的 `Calculator`（开销很小）；若要批量评分，直接循环构造即可：

```go
func calculateScore(vector *cvss.Cvss3x) (float64, error) {
    calc := cvss.NewCalculator(vector)
    return calc.Calculate()
}
```

### 3. 性能监控

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

## 相关文档

- [Calculator 详细文档](/zh/api/cvss/calculator)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [DistanceCalculator 详细文档](/zh/api/cvss/distance)
- [JSON 支持](/zh/api/cvss/json)
- [使用示例](/zh/examples/)
