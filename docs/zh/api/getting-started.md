# 快速开始

欢迎使用 CVSS Skills！本指南将在 5 分钟内帮你上手这个强大的 CVSS 解析和计算库。

## 三步心智模型

几乎每个程序都遵循同样的三步：**解析 → 计算 → 解读**。

```mermaid
flowchart LR
    A["1 · 解析<br/>NewCvss3xParser().Parse()"] --> B["2 · 计算<br/>NewCalculator().Calculate()"]
    B --> C["3 · 解读<br/>GetSeverityRating(score)"]
    C --> R(["9.8 → Critical"])

    classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    class A,B,C step;
```

## 安装

使用 Go modules 安装 CVSS Skills：

```bash
go get github.com/scagogogo/cvss-skills
```

## 第一个程序

创建一个新的 Go 文件 `main.go`：

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 1. 创建解析器
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    p := parser.NewCvss3xParser(vectorStr)

    // 2. 解析 CVSS 向量
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }

    // 3. 创建计算器
    calculator := cvss.NewCalculator(cvssVector)

    // 4. 计算评分
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatalf("计算失败: %v", err)
    }

    // 5. 获取严重性等级
    severity := calculator.GetSeverityRating(score)

    // 6. 输出结果
    fmt.Printf("CVSS 向量: %s\n", vectorStr)
    fmt.Printf("基础评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n", severity)
}
```

运行程序：

```bash
go run main.go
```

输出：
```
CVSS 向量: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
基础评分: 9.8
严重性: Critical
```

## 核心概念

### 1. CVSS 向量

CVSS 向量是一个描述漏洞特征的字符串：

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

- `CVSS:3.1` - 版本标识
- `AV:N` - 攻击向量：网络
- `AC:L` - 攻击复杂性：低
- `PR:N` - 所需权限：无
- `UI:N` - 用户交互：无
- `S:U` - 影响范围：不变
- `C:H` - 机密性影响：高
- `I:H` - 完整性影响：高
- `A:H` - 可用性影响：高

### 2. 解析器 (Parser)

解析器将 CVSS 向量字符串转换为结构化对象：

```go
// 创建解析器
p := parser.NewCvss3xParser(vectorString)

// 解析向量
cvssVector, err := p.Parse()
```

### 3. 计算器 (Calculator)

计算器根据解析后的向量计算 CVSS 评分：

```go
// 创建计算器
calculator := cvss.NewCalculator(cvssVector)

// 计算评分
score, err := calculator.Calculate()
```

## 常用功能

### 解析不同类型的向量

```go
// 基础向量
basic := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

// 包含时间指标的向量
temporal := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"

// 包含环境指标的向量
environmental := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"

vectors := []string{basic, temporal, environmental}

for _, vectorStr := range vectors {
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Printf("解析失败 %s: %v", vectorStr, err)
        continue
    }
    
    calculator := cvss.NewCalculator(vector)
    score, _ := calculator.Calculate()
    
    fmt.Printf("向量: %s\n", vectorStr)
    fmt.Printf("评分: %.1f\n", score)
    fmt.Printf("严重性: %s\n\n", calculator.GetSeverityRating(score))
}
```

### 获取详细信息

```go
// 获取向量的详细信息
fmt.Printf("CVSS 版本: %d.%d\n", cvssVector.MajorVersion, cvssVector.MinorVersion)
fmt.Printf("攻击向量: %s\n", cvssVector.Cvss3xBase.AttackVector.GetLongValue())
fmt.Printf("攻击复杂性: %s\n", cvssVector.Cvss3xBase.AttackComplexity.GetLongValue())
```

### 向量比较

```go
// 解析两个向量
vector1, _ := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").Parse()
vector2, _ := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L").Parse()

// 计算距离
distCalc := cvss.NewDistanceCalculator(vector1, vector2)
distance := distCalc.EuclideanDistance()

fmt.Printf("向量距离: %.3f\n", distance)
```

### JSON 序列化

```go
import "encoding/json"

// 序列化为 JSON
jsonData, err := json.MarshalIndent(cvssVector, "", "  ")
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))

// 从 JSON 反序列化
var newVector cvss.Cvss3x
err = json.Unmarshal(jsonData, &newVector)
if err != nil {
    log.Fatal(err)
}
```

## 错误处理

CVSS Skills 将解析错误以哨兵错误或 `fmt.Errorf` 形式返回，验证错误以 `cvss.ValidationErrors` 形式返回：

```go
cv, err := parser.ParseString(vectorStr)
if err != nil {
    if errors.Is(err, parser.ErrParserMagicHead) {
        fmt.Printf("不是 CVSS 向量（缺少 'CVSS:' 前缀）\n")
    }
    log.Fatal(err)
}

// 完整性检查独立于解析
if err := cv.Validate(); err != nil {
    if ve, ok := err.(cvss.ValidationErrors); ok {
        for _, m := range ve.MissingMetrics() {
            fmt.Printf("缺少指标: %s\n", m)
        }
    }
}
```

## 严重性等级

CVSS 评分对应的严重性等级：

| 评分范围 | 严重性等级 | 描述 |
|----------|------------|------|
| 0.0 | None | 无影响 |
| 0.1-3.9 | Low | 低危 |
| 4.0-6.9 | Medium | 中危 |
| 7.0-8.9 | High | 高危 |
| 9.0-10.0 | Critical | 严重 |

```go
score := 7.5
severity := calculator.GetSeverityRating(score)
fmt.Printf("评分 %.1f 对应严重性: %s\n", score, severity) // High
```

## 性能提示

### 1. 使用便捷函数

`Cvss3xParser` 在构造时绑定输入字符串，不可重用——没有 `SetVector`。单次解析请使用 `parser.ParseString`，它每次都构造新的解析器：

```go
// 好的做法：每个向量一次性解析
for _, vectorStr := range vectors {
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        continue
    }
    // 处理向量...
}
```

### 2. 批量处理

```go
func processBatch(vectors []string) {
    results := make([]float64, len(vectors))
    
    for i, vectorStr := range vectors {
        p := parser.NewCvss3xParser(vectorStr)
        vector, err := p.Parse()
        if err != nil {
            continue
        }
        
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            continue
        }
        
        results[i] = score
    }
    
    return results
}
```

## 下一步

现在你已经掌握了基础用法，可以继续学习：

1. **[API 详细文档](/zh/api/)** - 了解所有可用的 API
2. **[示例代码](/zh/examples/)** - 查看更多实际使用示例
3. **[CVSS 包详解](/zh/api/cvss/)** - 深入了解核心功能
4. **[最佳实践](/zh/api/getting-started)** - 生产环境使用建议

## 获取帮助

如果遇到问题：

- 查看 [常见问题](/zh/api/getting-started)
- 浏览 [GitHub Issues](https://github.com/scagogogo/cvss-skills/issues)
- 参与 [社区讨论](https://github.com/scagogogo/cvss-skills/discussions)
