# vector 包

`vector` 包提供了 CVSS 指标的统一接口和具体实现。它定义了所有 CVSS 3.x 指标的行为和属性，为解析器和计算器提供了基础的数据结构。

## 包概述

```go
import "github.com/scagogogo/cvss-skills/pkg/vector"
```

## 核心接口

### Vector 接口

所有 CVSS 指标都实现了 `Vector` 接口：

```go
type Vector interface {
    GetGroupName() string    // "Base Metrics" / "Temporal Metrics" / "Environmental Metrics"
    GetShortName() string    // 如 "AV"
    GetLongName() string     // 如 "Attack Vector"
    GetShortValue() rune     // 如 'N'
    GetLongValue() string    // 如 "Network"
    GetDescription() string  // CVSS 规范描述
    GetScore() float64       // 评分权重（Not Defined 为 1.0）
    IsNotDefined() bool      // 是否为 "Not Defined" (X)
    String() string          // 如 "AV:N"
}
```

详细文档：[Vector 接口](/zh/api/vector/interface)

## 指标分类

### 基础指标 (Base Metrics)

基础指标描述了漏洞的固有特征，不随时间或环境变化。

#### 可利用性指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 攻击向量 | AV | `AttackVector*` | Network, Adjacent, Local, Physical |
| 攻击复杂性 | AC | `AttackComplexity*` | Low, High |
| 所需权限 | PR | `PrivilegesRequired*` | None, Low, High |
| 用户交互 | UI | `UserInteraction*` | None, Required |

#### 影响指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 范围 | S | `Scope*` | Unchanged, Changed |
| 机密性影响 | C | `Confidentiality*` | None, Low, High |
| 完整性影响 | I | `Integrity*` | None, Low, High |
| 可用性影响 | A | `Availability*` | None, Low, High |

### 时间指标 (Temporal Metrics)

时间指标反映了漏洞随时间变化的特征。

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 利用代码成熟度 | E | `ExploitCodeMaturity*` | Not Defined, Unproven, Proof-of-Concept, Functional, High |
| 修复级别 | RL | `RemediationLevel*` | Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable |
| 报告置信度 | RC | `ReportConfidence*` | Not Defined, Unknown, Reasonable, Confirmed |

### 环境指标 (Environmental Metrics)

环境指标允许根据特定环境自定义评分。

#### 环境需求指标

| 指标 | 简称 | 实现类型 | 可能值 |
|------|------|----------|--------|
| 机密性需求 | CR | `ConfidentialityRequirement*` | Not Defined, Low, Medium, High |
| 完整性需求 | IR | `IntegrityRequirement*` | Not Defined, Low, Medium, High |
| 可用性需求 | AR | `AvailabilityRequirement*` | Not Defined, Low, Medium, High |

#### 修改后的基础指标

所有基础指标都有对应的修改版本，前缀为 `Modified`：

- `ModifiedAttackVector*`
- `ModifiedAttackComplexity*`
- `ModifiedPrivilegesRequired*`
- 等等...

## 使用示例

### 创建指标实例

每个合法的指标取值都作为预定义的包级变量（单例）暴露。直接引用即可 —— 无需构造：

```go
// 攻击向量 = Network
attackVector := vector.AttackVectorNetwork
fmt.Printf("攻击向量: %s (%s)\n",
    attackVector.GetLongValue(),
    attackVector.GetDescription())

// 攻击复杂性 = Low
attackComplexity := vector.AttackComplexityLow
fmt.Printf("攻击复杂性: %s (评分: %.2f)\n",
    attackComplexity.GetLongValue(),
    attackComplexity.GetScore())
```

也可以用[工厂函数](/zh/api/vector/interface#工厂函数)从短名/取值解析：

```go
av, err := vector.GetVectorByShortName("AV", "N")
if err != nil {
    log.Fatal(err)
}
fmt.Println(av.String()) // AV:N
```

### 使用接口

```go
func printVectorInfo(v vector.Vector) {
    fmt.Printf("指标: %s (%s)\n", v.GetLongName(), v.GetShortName())
    fmt.Printf("  组: %s\n", v.GetGroupName())
    fmt.Printf("  值: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  评分: %.2f\n", v.GetScore())
    fmt.Printf("  Not defined: %v\n", v.IsNotDefined())
    fmt.Printf("  字符串: %s\n", v.String())
}

// 使用示例
printVectorInfo(vector.AttackVectorNetwork)
```

### 向量工厂

包提供了从短值解析指标取值的工厂函数，对未知取值返回错误。每个指标一个工厂（如 `GetAttackVector`、`GetExploitCodeMaturity`），另有通用的 `GetVectorByShortName`：

```go
// 每指标工厂
av, err := vector.GetAttackVector('N')
if err != nil {
    log.Fatal(err)
}
fmt.Println(av.String()) // AV:N

// 按短名 + 取值字符串的通用工厂
e, err := vector.GetVectorByShortName("E", "F")
if err != nil {
    log.Fatal(err)
}
fmt.Println(e.String()) // E:F
```

## 指标详细信息

每个指标取值都是一个嵌入 `*VectorImpl` 的类型的预定义变量（见 [Vector 接口](/zh/api/vector/interface)）。下表列出规范单例及其评分权重。

### 攻击向量 (Attack Vector)

描述攻击者如何访问漏洞组件。

| 单例 | 短值 | 全值 | 评分 |
|------|------|------|------|
| `AttackVectorNetwork` | N | Network | 0.85 |
| `AttackVectorAdjacent` | A | Adjacent | 0.62 |
| `AttackVectorLocal` | L | Local | 0.55 |
| `AttackVectorPhysical` | P | Physical | 0.2 |

```go
av := vector.AttackVectorNetwork
fmt.Printf("%c %.2f\n", av.GetShortValue(), av.GetScore()) // N 0.85
```

### 攻击复杂性 (Attack Complexity)

描述攻击成功所需的条件。

| 单例 | 短值 | 全值 | 评分 |
|------|------|------|------|
| `AttackComplexityLow` | L | Low | 0.77 |
| `AttackComplexityHigh` | H | High | 0.44 |

### 影响指标

影响指标描述了成功攻击对系统的影响程度。

| 单例 | 短值 | 全值 | 评分 |
|------|------|------|------|
| `ConfidentialityHigh` | H | High | 0.56 |
| `ConfidentialityLow` | L | Low | 0.22 |
| `ConfidentialityNone` | N | None | 0.0 |

::: tip 依赖范围的指标
所需权限（`PR`）是唯一一个权重依赖 Scope 的基础指标。请使用 `vector.GetPrivilegesRequiredScore(pr, scopeChanged)` 而非 `pr.GetScore()` —— 见 [Vector 接口](/zh/api/vector/interface#getprivilegesrequiredscore)。
:::

## 向量验证

### 基本验证

```go
func validateVector(v vector.Vector) error {
    if v.GetShortName() == "" {
        return fmt.Errorf("指标简称不能为空")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("指标值不能为空")
    }
    
    score := v.GetScore()
    if score < 0 || score > 1 {
        return fmt.Errorf("指标评分必须在 0-1 之间，当前值: %.2f", score)
    }
    
    return nil
}
```

### 批量验证

```go
func validateVectors(vectors []vector.Vector) []error {
    var errors []error
    
    for i, v := range vectors {
        if err := validateVector(v); err != nil {
            errors = append(errors, fmt.Errorf("向量 %d 验证失败: %w", i, err))
        }
    }
    
    return errors
}
```

## 向量比较

### 基本比较

```go
func compareVectors(v1, v2 vector.Vector) {
    fmt.Printf("比较 %s 和 %s:\n", v1.String(), v2.String())
    
    if v1.GetShortName() != v2.GetShortName() {
        fmt.Println("  不同类型的指标，无法比较")
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

### 向量分组

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

## 扩展和自定义

### 自定义向量

实现自定义指标时，嵌入 `*vector.VectorImpl` —— 它已提供全部 `Vector` 接口方法，你只需填字段：

```go
// 由 VectorImpl 支撑的自定义向量实现
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

### 向量注册表

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

## 性能优化

### 向量缓存

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

### 无需对象池

预定义单例是不可变的包级值，被所有调用方共享 —— 没有可池化的对象。工厂函数解析取值只是返回已有单例的廉价 `switch`，每次调用本质上只是一次指针拷贝。不要把它们包进 `sync.Pool`；直接调用 `vector.GetAttackVector('N')` 或引用 `vector.AttackVectorNetwork` 即可。

## 最佳实践

### 1. 类型安全

```go
func getAttackVectorScore(v vector.Vector) (float64, error) {
    if v.GetShortName() != "AV" {
        return 0, fmt.Errorf("不是攻击向量指标")
    }
    return v.GetScore(), nil
}
```

### 2. 空值处理

```go
func safeGetScore(v vector.Vector) float64 {
    if v == nil {
        return 0.0
    }
    return v.GetScore()
}
```

### 3. 接口组合

`Vector` 接口是有意保持扁平的 —— 它不拆分为子接口。若需更窄的视图（例如仅评分方法），在自己的代码中定义本地接口并断言：

```go
// 应用特定的更窄接口
type Scorer interface {
    GetScore() float64
    IsNotDefined() bool
}

func scoreOf(s Scorer) float64 {
    if s.IsNotDefined() {
        return 1.0 // 无操作权重
    }
    return s.GetScore()
}
```

## 相关文档

- [Vector 接口详解](/zh/api/vector/interface)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [Parser 解析器](/zh/api/parser/cvss3x-parser)
- [使用示例](/zh/examples/basic)
