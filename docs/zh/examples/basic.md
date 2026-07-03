# 基础用法示例

这个示例演示了 CVSS Skills 的最基本用法：解析 CVSS 向量字符串并计算评分。

## 示例代码

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // =====================================================
    // CVSS解析器基础用法示例
    // 演示如何解析CVSS向量字符串并获取其基本信息和评分
    // =====================================================

    // 示例CVSS向量字符串 - 关键级别(Critical)，评分为9.8
    cvssVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    fmt.Println("示例CVSS向量:", cvssVector)
    fmt.Println("=====================================================")

    // 第1步: 创建解析器
    p := parser.NewCvss3xParser(cvssVector)

    // 第2步: 解析CVSS向量
    cvss3x, err := p.Parse()
    if err != nil {
        log.Fatalf("解析CVSS向量失败: %v", err)
    }

    // 第3步: 输出解析结果
    fmt.Println("解析结果:")
    fmt.Printf("  CVSS版本: %d.%d\n", cvss3x.MajorVersion, cvss3x.MinorVersion)
    fmt.Println("\n基础指标:")
    fmt.Printf("  攻击向量(AV): %s\n", cvss3x.Cvss3xBase.AttackVector.GetLongValue())
    fmt.Printf("  攻击复杂性(AC): %s\n", cvss3x.Cvss3xBase.AttackComplexity.GetLongValue())
    fmt.Printf("  权限要求(PR): %s\n", cvss3x.Cvss3xBase.PrivilegesRequired.GetLongValue())
    fmt.Printf("  用户交互(UI): %s\n", cvss3x.Cvss3xBase.UserInteraction.GetLongValue())
    fmt.Printf("  范围(S): %s\n", cvss3x.Cvss3xBase.Scope.GetLongValue())
    fmt.Printf("  机密性(C): %s\n", cvss3x.Cvss3xBase.Confidentiality.GetLongValue())
    fmt.Printf("  完整性(I): %s\n", cvss3x.Cvss3xBase.Integrity.GetLongValue())
    fmt.Printf("  可用性(A): %s\n", cvss3x.Cvss3xBase.Availability.GetLongValue())

    // 第4步: 创建计算器并计算CVSS评分
    calculator := cvss.NewCalculator(cvss3x)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算CVSS评分失败: %v", err)
    }

    // 第5步: 获取严重性等级
    severity := calculator.GetSeverityRating(score)
    fmt.Printf("\nCVSS评分: %.1f\n", score)
    fmt.Printf("严重性等级: %s\n", severity)

    // 第6步: 将CVSS对象转换回向量字符串
    fmt.Printf("\n原始向量: %s\n", cvssVector)
    fmt.Printf("重构向量: %s\n", cvss3x.String())

    fmt.Println("\n=====================================================")
    fmt.Println("基础用法示例结束")
    fmt.Println("运行其他示例以了解更多功能")
}
```

## 运行示例

```bash
# 进入项目目录
cd cvss

# 运行基础示例
go run examples/01_basic/main.go
```

## 预期输出

```
示例CVSS向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
=====================================================
解析结果:
  CVSS版本: 3.1

基础指标:
  攻击向量(AV): Network
  攻击复杂性(AC): Low
  权限要求(PR): None
  用户交互(UI): None
  范围(S): Unchanged
  机密性(C): High
  完整性(I): High
  可用性(A): High

CVSS评分: 9.8
严重性等级: Critical

原始向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
重构向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

=====================================================
基础用法示例结束
运行其他示例以了解更多功能
```

## 代码解析

### 1. 创建解析器

```go
p := parser.NewCvss3xParser(cvssVector)
```

创建一个新的 CVSS 3.x 解析器实例，传入要解析的向量字符串。

### 2. 解析向量

```go
cvss3x, err := p.Parse()
```

调用 `Parse()` 方法解析向量字符串，返回结构化的 CVSS 对象和可能的错误。

### 3. 访问解析结果

```go
fmt.Printf("CVSS版本: %d.%d\n", cvss3x.MajorVersion, cvss3x.MinorVersion)
fmt.Printf("攻击向量(AV): %s\n", cvss3x.Cvss3xBase.AttackVector.GetLongValue())
```

通过 CVSS 对象的字段和方法访问各种信息：
- `MajorVersion`, `MinorVersion`: 版本信息
- `Cvss3xBase.*`: 基础指标
- `GetLongValue()`: 获取指标的完整描述

### 4. 计算评分

```go
calculator := cvss.NewCalculator(cvss3x)
score, err := calculator.Calculate()
```

创建计算器并计算 CVSS 评分。计算器会根据向量中的指标自动选择合适的计算方法。

### 5. 获取严重性等级

```go
severity := calculator.GetSeverityRating(score)
```

根据评分获取对应的严重性等级（None、Low、Medium、High、Critical）。

### 6. 向量字符串转换

```go
fmt.Printf("重构向量: %s\n", cvss3x.String())
```

将 CVSS 对象转换回标准的向量字符串格式。

## 关键概念

### CVSS 向量格式

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

- `CVSS:3.1`: 版本标识
- `AV:N`: 攻击向量为网络 (Network)
- `AC:L`: 攻击复杂性为低 (Low)
- `PR:N`: 所需权限为无 (None)
- `UI:N`: 用户交互为无 (None)
- `S:U`: 影响范围不变 (Unchanged)
- `C:H`: 机密性影响为高 (High)
- `I:H`: 完整性影响为高 (High)
- `A:H`: 可用性影响为高 (High)

### 严重性等级

| 评分范围 | 严重性等级 | 描述 |
|----------|------------|------|
| 0.0 | None | 无影响 |
| 0.1-3.9 | Low | 低危 |
| 4.0-6.9 | Medium | 中危 |
| 7.0-8.9 | High | 高危 |
| 9.0-10.0 | Critical | 严重 |

## 错误处理

示例中包含了基本的错误处理：

```go
if err != nil {
    log.Fatalf("解析CVSS向量失败: %v", err)
}
```

常见的错误包括：
- 向量格式不正确
- 版本号不支持
- 指标值无效
- 缺少必需的指标

## 扩展练习

尝试修改示例代码：

1. **更换向量**: 使用不同的 CVSS 向量字符串
2. **添加验证**: 在解析后验证向量的完整性
3. **批量处理**: 解析多个向量并比较评分
4. **错误处理**: 添加更详细的错误处理逻辑

### 练习1: 不同严重性的向量

```go
vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // Critical
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  // High
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",  // Low
}

for _, vector := range vectors {
    // 解析和计算每个向量
}
```

### 练习2: 详细的指标分析

```go
// 输出每个指标的评分
fmt.Printf("攻击向量评分: %.2f\n", cvss3x.Cvss3xBase.AttackVector.GetScore())
fmt.Printf("攻击复杂性评分: %.2f\n", cvss3x.Cvss3xBase.AttackComplexity.GetScore())
// ... 其他指标
```

## 下一步

完成基础示例后，可以继续学习：

- [解析向量](/zh/examples/parsing) - 学习解析不同格式的向量
- [JSON 输出](/zh/examples/json) - 了解数据序列化
- [距离计算](/zh/examples/distance) - 学习向量比较功能
- [高级示例](/zh/examples/edge-cases) - 错误处理和边缘情况

## 相关文档

- [Cvss3xParser API](/zh/api/parser/cvss3x-parser)
- [Calculator API](/zh/api/cvss/calculator)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
