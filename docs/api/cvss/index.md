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

## 功能特性

### 🎯 完整的 CVSS 支持

- **CVSS 3.0/3.1**: 完全支持两个版本
- **所有指标**: 基础、时间、环境指标
- **精确计算**: 严格按照官方规范

### 📊 高级分析

- **距离计算**: 多种距离算法
- **相似度分析**: 向量相似度评估
- **批量处理**: 高效的批量计算

### 🔧 开发者友好

- **类型安全**: 强类型 API 设计
- **零依赖**: 纯 Go 实现
- **高性能**: 优化的计算算法

## 包结构

```
cvss/
├── cvss3x.go              # 主要数据结构
├── cvss3x_base.go         # 基础指标
├── cvss3x_temporal.go     # 时间指标
├── cvss3x_environmental.go # 环境指标
├── calculator.go          # 评分计算器
├── distance.go           # 距离计算器
└── json.go               # JSON 支持
```

## 设计模式

### 组合模式
CVSS 向量使用组合模式，将不同类型的指标组合在一起：

```go
type Cvss3x struct {
    *Cvss3xBase          // 基础指标
    *Cvss3xTemporal      // 时间指标
    *Cvss3xEnvironmental // 环境指标
    
    MajorVersion int     // 主版本号
    MinorVersion int     // 次版本号
}
```

### 策略模式
不同的计算算法使用策略模式实现：

```go
// 基础评分计算
func (c *Calculator) calculateBaseScore() float64 {
    if c.isChangedScope() {
        return c.calculateChangedScopeScore()
    }
    return c.calculateUnchangedScopeScore()
}
```

### 工厂模式
提供便捷的构造函数：

```go
// 创建新的 CVSS 向量
func NewCvss3x() *Cvss3x

// 创建计算器
func NewCalculator(cvss *Cvss3x) *Calculator

// 创建距离计算器
func NewDistanceCalculator(v1, v2 *Cvss3x) *DistanceCalculator
```

## 性能考虑

### 内存效率
- 使用指针避免不必要的复制
- 延迟初始化可选指标
- 最小化内存分配

### 计算优化
- 缓存中间计算结果
- 避免重复计算
- 使用高效的数学运算

## 下一步

深入了解具体功能：

- 📖 [Cvss3x 数据结构](/api/cvss/cvss3x)
- 🧮 [Calculator 评分计算](/api/cvss/calculator)
- 📏 [DistanceCalculator 距离计算](/api/cvss/distance)
- 📄 [JSON 支持](/api/cvss/json)
