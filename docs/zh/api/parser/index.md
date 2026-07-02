# parser 包

`parser` 包提供了将 CVSS 向量字符串解析为结构化对象的功能。它支持 CVSS 3.0 和 3.1 版本，字符串在构造时绑定，解析器一次性消费。

## 包概述

```go
import "github.com/scagogogo/cvss-skills/pkg/parser"
```

## 主要类型

### 解析器

| 类型 | 描述 | 文档链接 |
|------|------|----------|
| `Cvss3xParser` | CVSS 3.x 向量解析器（字符串在构造时绑定） | [详细文档](/zh/api/parser/cvss3x-parser) |
| `VectorParser` | 指标名/值到 `vector.Vector` 的注册表（结构体，非接口） | — |

::: tip 没有 Parser 接口
本包没有通用的 `Parser` 接口，`VectorParser` 也是结构体而非接口。`Cvss3xParser` 是面向 CVSS 3.x 向量字符串的解析入口。
:::

## 快速开始

### 基本解析

```go
vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
p := parser.NewCvss3xParser(vectorStr)

vector, err := p.Parse()
if err != nil {
    log.Fatalf("解析失败: %v", err)
}

fmt.Printf("解析成功: %s\n", vector.String())
```

### 便捷函数

`parser` 包提供一行简写，内部各自构造新的解析器：

| 函数 | 签名 | 行为 |
|------|------|------|
| `ParseString` | `(str string) (*cvss.Cvss3x, error)` | `NewCvss3xParser(str).Parse()` |
| `MustParse` | `(str string) *cvss.Cvss3x` | 同 `ParseString`，但出错时 panic |
| `ParseRelaxed` | `(str, defaultVersion string) (*cvss.Cvss3x, error)` | 接受不带 `CVSS:3.1/` 前缀的字符串；自动补 `CVSS:<defaultVersion>/`（默认 `"3.1"`） |
| `ParseAndValidate` | `(str string) (*cvss.Cvss3x, error)` | 解析后 `Validate()`，缺少基础指标则失败 |
| `ParseAndScore` | `(str string) (*cvss.Cvss3x, float64, cvss.Severity, error)` | 解析并计算基础评分与严重性 |

### 批量解析

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
    "not-a-vector",
}, 4)

for _, r := range results {
    if r.Error != nil {
        fmt.Printf("索引 %d 失败: %v\n", r.Index, r.Error)
        continue
    }
    fmt.Printf("索引 %d 成功: %s\n", r.Index, r.Vector.String())
}
```

## 解析流程

```mermaid
flowchart TD
    In["CVSS:3.1/AV:N/AC:L/..."] --> Head{"以 'CVSS:' 开头?"}
    Head -->|否| Err1["ErrParserMagicHead"]
    Head -->|是| Ver{版本 3.0 / 3.1?}
    Ver -->|否| ErrV["fmt.Errorf：<br/>不支持的版本"]
    Ver -->|是| Loop
    Loop["对每个 /KEY:VALUE"] --> Dup{已见过 KEY?}
    Dup -->|是| ErrD["ErrDuplicateMetric"]
    Dup -->|否| Known{GetVectorByShortName<br/>认识 KEY:VALUE?}
    Known -->|否| Err2["fmt.Errorf：<br/>未知/非法值"]
    Known -->|是| Set["设置指标"]
    Set --> Loop
    Loop -->|结束| Out(["*cvss.Cvss3x"])
    Out --> Check{Check() / Validate()}
    Check -->|缺少基础指标| Err3["cvss.ValidationErrors<br/>MissingMetrics()"]

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class Err1,ErrV,ErrD,Err2,Err3 err;
```

::: warning Parse 本身不强制完整性
`Parse()` 即使缺少基础指标也会返回 `*Cvss3x`。如需强制必需基础指标，解析后调用 `Check()`（返回首个缺失指标）或 `Validate()`（返回 `cvss.ValidationErrors`，含全部缺失项）。
:::

## 错误处理

### 哨兵错误

```go
var ErrParserMagicHead = errors.New("cvss 3.x parser error: invalid magic head, it must equal 'CVSS'")
var ErrDuplicateMetric = errors.New("cvss 3.x parser error: duplicate metric key")
```

用 `errors.Is` 检测：

```go
vector, err := p.Parse()
if err != nil {
    if errors.Is(err, parser.ErrParserMagicHead) {
        log.Fatal("输入不是 CVSS 向量（缺少 'CVSS:' 前缀）")
    }
    if errors.Is(err, parser.ErrDuplicateMetric) {
        log.Fatalf("重复指标: %v", err)
    }
    // 否则是描述不支持版本、未知指标名或非法值的 fmt.Errorf
    log.Fatal(err)
}
```

### 解析后的验证错误

完整性由 `cvss` 包检查，而非解析器：

```go
cv, err := parser.ParseString(vectorStr)
if err != nil {
    return err
}
if err := cv.Validate(); err != nil {
    if ve, ok := err.(cvss.ValidationErrors); ok {
        for _, m := range ve.MissingMetrics() {
            fmt.Printf("缺少指标: %s\n", m)
        }
    }
}
```

::: tip 没有位置型 ParseError
本包不返回带 `Position`/`Input` 字段的 `*parser.ParseError`。所有解析错误要么是上述哨兵错误，要么是普通 `fmt.Errorf` 文本。
:::

## 支持的格式

### 标准格式

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### 包含时间指标

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
```

### 包含环境指标

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L
```

### 完整向量

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
```

## 性能优化

### 并发解析

`Cvss3xParser` 持有可变游标状态，**不可**跨 goroutine 共享同一实例。每个向量构造新的解析器（或直接用 `BatchParse`）：

```go
func parseVectorsConcurrently(vectors []string) []*cvss.Cvss3x {
    results := make([]*cvss.Cvss3x, len(vectors))
    var wg sync.WaitGroup

    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, s string) {
            defer wg.Done()
            cv, err := parser.ParseString(s) // 每个 goroutine 用新解析器
            if err != nil {
                results[index] = nil
                return
            }
            results[index] = cv
        }(i, vectorStr)
    }

    wg.Wait()
    return results
}
```

::: warning 不要用对象池复用解析器
通过 `sync.Pool` 复用 `*Cvss3xParser` 并配合不存在的 `SetVector` 来重设输入字符串是不支持的——输入字符串在构造时即固定。池化普通字符串并调用 `ParseString` 没问题；池化解析器对象则不行。
:::

## 最佳实践

### 1. 错误处理

```go
func safeParseVector(vectorStr string) (*cvss.Cvss3x, error) {
    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        return nil, fmt.Errorf("解析向量失败 '%s': %w", vectorStr, err)
    }

    // 额外验证完整性
    if err := cv.Check(); err != nil {
        return nil, fmt.Errorf("向量验证失败: %w", err)
    }

    return cv, nil
}
```

### 2. 输入验证

```go
func validateInput(vectorStr string) error {
    if vectorStr == "" {
        return fmt.Errorf("向量字符串不能为空")
    }

    if len(vectorStr) > 1000 {
        return fmt.Errorf("向量字符串过长")
    }

    if !strings.HasPrefix(strings.ToUpper(vectorStr), "CVSS:") {
        // ParseRelaxed 可处理无前缀输入；否则视为错误
        return fmt.Errorf("无效的向量格式（缺少 'CVSS:' 前缀）")
    }

    return nil
}
```

## 相关文档

- [Cvss3xParser 详细文档](/zh/api/parser/cvss3x-parser)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [使用示例](/zh/examples/parsing)
- [错误处理指南](/zh/api/cvss/)
