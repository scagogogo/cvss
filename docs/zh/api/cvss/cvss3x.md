# Cvss3x 数据结构

`Cvss3x` 是 CVSS Skills 中表示 CVSS 3.x 向量的核心数据结构。它包含了完整的 CVSS 向量信息，包括版本、基础指标、时间指标和环境指标。

## 结构定义

`Cvss3x` 以嵌入指针的形式持有三个指标组，并携带版本号。字段本身无 json tag —— JSON 序列化由自定义的 `MarshalJSON` 处理（输出向量字符串，详见 [JSON 支持](/zh/api/cvss/json)），而非依赖结构体标签：

```go
type Cvss3x struct {
    *Cvss3xBase           // 嵌入 —— 基础指标（必需）
    *Cvss3xTemporal       // 嵌入 —— 时间指标（可选，无则为 nil）
    *Cvss3xEnvironmental  // 嵌入 —— 环境指标（可选，无则为 nil）

    MajorVersion int      // 始终为 3
    MinorVersion int      // 0（CVSS 3.0）或 1（CVSS 3.1）
}
```

## 字段说明

### 版本信息

| 字段 | 类型 | 描述 | 示例 |
|------|------|------|------|
| `MajorVersion` | `int` | CVSS 主版本号 | `3` |
| `MinorVersion` | `int` | CVSS 次版本号 | `1` |

### 指标组

| 字段 | 类型 | 描述 | 必需 |
|------|------|------|------|
| `Cvss3xBase` | `*Cvss3xBase` | 基础指标组 | ✅ |
| `Cvss3xTemporal` | `*Cvss3xTemporal` | 时间指标组 | ❌ |
| `Cvss3xEnvironmental` | `*Cvss3xEnvironmental` | 环境指标组 | ❌ |

## 基础指标组 (Cvss3xBase)

基础指标组包含了描述漏洞固有特征的指标，这些指标在时间和环境变化时保持不变。

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

`vector.Vector` 是一个接口。每个指标值都是 `pkg/vector` 中预声明的指针变量（如 `vector.AttackVectorNetwork`、`vector.ConfidentialityHigh`）—— 直接赋值该变量即可，**不要**对其取地址或实例化。

### 可利用性指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 攻击向量 | AV | 攻击者访问漏洞的方式 | Network(N), Adjacent(A), Local(L), Physical(P) |
| 攻击复杂性 | AC | 攻击的复杂程度 | Low(L), High(H) |
| 所需权限 | PR | 攻击前需要的权限级别 | None(N), Low(L), High(H) |
| 用户交互 | UI | 是否需要用户参与 | None(N), Required(R) |

### 影响指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 范围 | S | 漏洞是否影响其他组件 | Unchanged(U), Changed(C) |
| 机密性影响 | C | 对信息机密性的影响 | None(N), Low(L), High(H) |
| 完整性影响 | I | 对信息完整性的影响 | None(N), Low(L), High(H) |
| 可用性影响 | A | 对系统可用性的影响 | None(N), Low(L), High(H) |

## 时间指标组 (Cvss3xTemporal)

时间指标组反映了漏洞随时间变化的特征。

```go
type Cvss3xTemporal struct {
    ExploitCodeMaturity vector.Vector
    RemediationLevel    vector.Vector
    ReportConfidence    vector.Vector
}
```

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 利用代码成熟度 | E | 可用利用代码的成熟程度 | Not Defined(X), Unproven(U), Proof-of-Concept(P), Functional(F), High(H) |
| 修复级别 | RL | 可用修复措施的级别 | Not Defined(X), Official Fix(O), Temporary Fix(T), Workaround(W), Unavailable(U) |
| 报告置信度 | RC | 漏洞报告的置信程度 | Not Defined(X), Unknown(U), Reasonable(R), Confirmed(C) |

## 环境指标组 (Cvss3xEnvironmental)

环境指标组允许分析师根据特定环境自定义 CVSS 评分。

```go
type Cvss3xEnvironmental struct {
    // 环境需求指标
    ConfidentialityRequirement vector.Vector
    IntegrityRequirement       vector.Vector
    AvailabilityRequirement    vector.Vector

    // 修改后的基础指标
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

### 环境需求指标

| 指标 | 简称 | 描述 | 可能值 |
|------|------|------|--------|
| 机密性需求 | CR | 受影响系统机密性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |
| 完整性需求 | IR | 受影响系统完整性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |
| 可用性需求 | AR | 受影响系统可用性的重要程度 | Not Defined(X), Low(L), Medium(M), High(H) |

### 修改后的基础指标

修改后的基础指标允许分析师根据特定环境调整基础指标值。如果未指定，则使用原始基础指标值。

## 主要方法

### String

```go
func (c *Cvss3x) String() string
```

将 CVSS 向量转换为标准的字符串表示形式。

**示例：**
```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
fmt.Println(cv.String()) // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### IsComplete

```go
func (x *Cvss3x) IsComplete() bool
```

检查 8 个必需的基础指标是否全部已设置。不校验取值，也不检查版本/可选指标 —— 完整结构校验请用 `Validate()`。

**返回值：**
- `bool`: 所有基础指标均非 nil 时为 true

**示例：**
```go
if cv.IsComplete() {
    fmt.Println("所有基础指标已设置")
} else {
    fmt.Println("不完整，缺失:", cv.MissingMetrics())
}
```

### Version

```go
func (x *Cvss3x) Version() string
```

返回格式为 `"<主版本>.<次版本>"` 的版本字符串。

**返回值：**
- `string`: 版本字符串（如 `"3.1"`）

**示例：**
```go
fmt.Printf("CVSS 版本: %s\n", cv.Version()) // "3.1"
```

### HasTemporalMetrics

```go
func (x *Cvss3x) HasTemporalMetrics() bool
```

检查是否设置了任何时间指标（`E`、`RL`、`RC`）。

**返回值：**
- `bool`: 至少存在一个时间指标时为 true

**示例：**
```go
if cv.HasTemporalMetrics() {
    fmt.Println("向量包含时间指标")
}
```

### HasEnvironmentalMetrics

```go
func (x *Cvss3x) HasEnvironmentalMetrics() bool
```

检查是否设置了任何环境指标。

**返回值：**
- `bool`: 至少存在一个环境指标时为 true

**示例：**
```go
if cv.HasEnvironmentalMetrics() {
    fmt.Println("向量包含环境指标")
}
```

### Check

```go
func (x *Cvss3x) Check() error
```

对向量做结构校验：版本号受支持（3.0/3.1）、基础指标组存在且完整、已存在的时间/环境指标组取值合法。返回遇到的第一个错误，若无问题返回 nil。如需收集全部错误（含缺失指标报告），请用 `Validate()`。

**返回值：**
- `error`: 第一个校验错误，或 nil

**示例：**
```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err := cv.Check(); err != nil {
    log.Fatalf("向量校验失败: %v", err)
}
```

### Clone

```go
func (c *Cvss3x) Clone() *Cvss3x
```

创建 CVSS 向量的深拷贝。

**示例：**
```go
original, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cloned := original.Clone()

// 修改克隆的向量不会影响原始向量（Clone 是深拷贝）
cloned.Cvss3xBase.AttackVector = vector.AttackVectorLocal
fmt.Printf("原始 AV: %c, 克隆 AV: %c\n",
    original.Cvss3xBase.AttackVector.GetShortValue(),
    cloned.Cvss3xBase.AttackVector.GetShortValue()) // 原始 AV: N, 克隆 AV: L
```

## 创建和初始化

### 手动创建

```go
cv := cvss.NewCvss3x()
cv.MajorVersion = 3
cv.MinorVersion = 1

cv.Cvss3xBase = &cvss.Cvss3xBase{
    AttackVector:       vector.AttackVectorNetwork,
    AttackComplexity:   vector.AttackComplexityLow,
    PrivilegesRequired: vector.PrivilegesRequiredNone,
    UserInteraction:    vector.UserInteractionNone,
    Scope:              vector.ScopeUnchanged,
    Confidentiality:    vector.ConfidentialityHigh,
    Integrity:          vector.IntegrityHigh,
    Availability:       vector.AvailabilityHigh,
}
```

### 使用构建器模式

CVSS Skills 内置流式构建器 `cvss.NewBuilder()`。每个方法接收一个 `rune` 短值（如 `'N'` 表示 AV Network），并立即校验；`Build()` 返回错误，`MustBuild()` 在出错时 panic：

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

## JSON 序列化

`Cvss3x` 实现了自定义的 `MarshalJSON` / `UnmarshalJSON`：JSON 表示就是**向量字符串本身**（一个 JSON 字符串），而非结构化对象。

### 序列化

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// 序列化为 JSON —— 输出 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
jsonData, err := json.Marshal(cv)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

### 反序列化

```go
// JSON 内容是一个向量字符串
jsonStr := []byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`)

var cv cvss.Cvss3x
if err := json.Unmarshal(jsonStr, &cv); err != nil {
    log.Fatal(err)
}
fmt.Println(cv.String())
```

::: tip 需要带评分的结构化 JSON？
若要同时输出评分、严重性与各指标明细，请使用 `cv.ToJSON(calculator)`（接受一个 `*Calculator`），它返回带 `version`/`vectorString`/`baseScore`/`metrics` 等字段的结构化 JSON。详见 [JSON 支持](/zh/api/cvss/json)。
:::

## 使用示例

### 完整示例

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    // 创建 CVSS 向量
    cvssVector := cvss.NewCvss3x()
    cvssVector.MajorVersion = 3
    cvssVector.MinorVersion = 1
    cvssVector.Cvss3xBase = &cvss.Cvss3xBase{
        AttackVector:       vector.AttackVectorNetwork,
        AttackComplexity:   vector.AttackComplexityLow,
        PrivilegesRequired: vector.PrivilegesRequiredNone,
        UserInteraction:    vector.UserInteractionNone,
        Scope:              vector.ScopeUnchanged,
        Confidentiality:    vector.ConfidentialityHigh,
        Integrity:          vector.IntegrityHigh,
        Availability:       vector.AvailabilityHigh,
    }

    // 验证向量
    if err := cvssVector.Check(); err != nil {
        log.Fatalf("向量验证失败: %v", err)
    }

    // 转换为字符串
    fmt.Printf("CVSS 向量: %s\n", cvssVector.String())

    // 序列化为 JSON（输出向量字符串）
    jsonData, err := json.Marshal(cvssVector)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("JSON 表示: %s\n", string(jsonData))

    // 计算评分
    calculator := cvss.NewCalculator(cvssVector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CVSS 评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", calculator.GetSeverityRating(score))
}
```

### 向量比较

```go
func compareVectors(v1, v2 *cvss.Cvss3x) {
    fmt.Printf("向量1: %s\n", v1.String())
    fmt.Printf("向量2: %s\n", v2.String())
    
    // 计算评分
    calc1 := cvss.NewCalculator(v1)
    calc2 := cvss.NewCalculator(v2)
    
    score1, _ := calc1.Calculate()
    score2, _ := calc2.Calculate()
    
    fmt.Printf("评分1: %.1f (%s)\n", score1, calc1.GetSeverityRating(score1))
    fmt.Printf("评分2: %.1f (%s)\n", score2, calc2.GetSeverityRating(score2))
    
    // 计算距离
    distCalc := cvss.NewDistanceCalculator(v1, v2)
    distance := distCalc.EuclideanDistance()
    
    fmt.Printf("向量距离: %.3f\n", distance)
}
```

## 最佳实践

### 1. 验证向量

```go
func validateAndProcess(vector *cvss.Cvss3x) error {
    // 总是验证向量
    if err := vector.Check(); err != nil {
        return fmt.Errorf("向量验证失败: %w", err)
    }
    
    // 处理向量...
    return nil
}
```

### 2. 安全的类型断言

```go
func getAttackVectorScore(vector *cvss.Cvss3x) (float64, error) {
    if vector.Cvss3xBase == nil || vector.Cvss3xBase.AttackVector == nil {
        return 0, fmt.Errorf("缺少攻击向量指标")
    }
    
    return vector.Cvss3xBase.AttackVector.GetScore(), nil
}
```

### 3. 深拷贝

```go
func modifyVector(original *cvss.Cvss3x) *cvss.Cvss3x {
    // 创建深拷贝以避免修改原始向量
    modified := original.Clone()
    
    // 安全地修改拷贝
    modified.MinorVersion = 2
    
    return modified
}
```

## 相关文档

- [Calculator 计算器](/zh/api/cvss/calculator) - 评分计算
- [DistanceCalculator 距离计算](/zh/api/cvss/distance) - 向量比较
- [JSON 支持](/zh/api/cvss/json) - 序列化
- [Parser 解析器](/zh/api/parser/cvss3x-parser) - 字符串解析
