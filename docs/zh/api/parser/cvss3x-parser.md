# Cvss3xParser - CVSS 3.x 解析器

`Cvss3xParser` 是专门用于解析 CVSS 3.x 向量字符串的解析器。字符串在构造时绑定，解析器通过 `Parse()` 一次性消费。

## 解析流程

解析器读取 `CVSS:` 魔术头、版本号，再逐个处理 `/KEY:VALUE` 段。未知指标名和非法取值会作为错误返回，解析器不会静默丢弃：

```mermaid
flowchart TD
    In["CVSS:3.1/AV:N/AC:L/..."] --> Head{"以 'CVSS:' 开头?"}
    Head -->|否| Err1["ErrParserMagicHead"]
    Head -->|是| Ver{版本 3.0 / 3.1?}
    Ver -->|否| ErrV["fmt.Errorf：<br/>不支持的版本"]
    Ver -->|是| Loop
    Loop["遍历每个 /KEY:VALUE"] --> Dup{已见过 KEY?}
    Dup -->|是| ErrD["ErrDuplicateMetric"]
    Dup -->|否| Known{GetVectorByShortName<br/>认识 KEY:VALUE?}
    Known -->|否| Err2["fmt.Errorf：<br/>未知/非法值"]
    Known -->|是| Set["在 Cvss3x 上设置指标"]
    Set --> Loop
    Loop -->|结束| Out(["*cvss.Cvss3x"])
    Out --> Check{Check() / Validate()}
    Check -->|缺少基础指标| Err3["cvss.ValidationErrors<br/>MissingMetrics()"]

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class Err1,ErrV,ErrD,Err2,Err3 err;
```

注意：`Parse()` 本身**不**强制完整性——即使缺少基础指标也会返回 `*Cvss3x`。如需强制必需基础指标，解析后调用 `Check()`（返回首个缺失指标）或 `Validate()`（返回 `cvss.ValidationErrors`，含全部缺失项）。

## 类型定义

`Cvss3xParser` 持有输入字符串与解析游标，字段均为非导出；通过 `NewCvss3xParser` 构造、`Parse` 消费：

```go
type Cvss3xParser struct {
    // 非导出：输入字符串、rune 游标、已解析键集合、结果 *cvss.Cvss3x
}

func NewCvss3xParser(cvss3xStr string) *Cvss3xParser
func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

## 创建解析器

### NewCvss3xParser

```go
func NewCvss3xParser(cvss3xStr string) *Cvss3xParser
```

创建绑定到给定向量字符串的 CVSS 3.x 解析器。字符串会去除首尾空白。

**参数：**
- `cvss3xStr`: 要解析的 CVSS 向量字符串

**返回值：**
- `*Cvss3xParser`: 解析器实例

**示例：**
```go
p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

::: warning 没有 SetVector —— 解析器不可重用
输入字符串在构造时即固定，没有 `SetVector` 方法可重新绑定。如需解析另一个向量，请构造新的解析器（开销很小）或使用 `parser.ParseString` 便捷函数。
:::

## 主要方法

### Parse

```go
func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

解析绑定的向量字符串并返回结构化的 `*cvss.Cvss3x`。对于非法魔术头、不支持的版本、重复指标键、未知指标名或非法指标值，返回错误。

**返回值：**
- `*cvss.Cvss3x`: 解析后的 CVSS 向量对象（错误为 nil 时必然非 nil）
- `error`: 解析错误——哨兵错误（`ErrParserMagicHead`、`ErrDuplicateMetric`）或描述问题的 `fmt.Errorf`

**示例：**
```go
vector, err := p.Parse()
if err != nil {
    log.Fatalf("解析失败: %v", err)
}
fmt.Printf("解析成功: %s\n", vector.String())
```

## 便捷函数

`parser` 包提供一行简写，内部各自构造新的解析器，部分还会一步完成验证或评分：

| 函数 | 签名 | 行为 |
|------|------|------|
| `ParseString` | `(str string) (*cvss.Cvss3x, error)` | `NewCvss3xParser(str).Parse()` |
| `MustParse` | `(str string) *cvss.Cvss3x` | 同 `ParseString`，但出错时 panic |
| `ParseRelaxed` | `(str, defaultVersion string) (*cvss.Cvss3x, error)` | 接受不带 `CVSS:3.1/` 前缀的字符串；自动补 `CVSS:<defaultVersion>/`（默认 `"3.1"`） |
| `ParseAndValidate` | `(str string) (*cvss.Cvss3x, error)` | 解析后 `Validate()`——缺少基础指标则失败 |
| `ParseAndScore` | `(str string) (*cvss.Cvss3x, float64, cvss.Severity, error)` | 解析并计算基础评分与严重性 |

```go
// 一行解析
cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// 无前缀输入
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")

// 解析 + 验证（拒绝不完整向量）
cv, err := parser.ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// 解析 + 评分
cv, score, severity, err := parser.ParseAndScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## 错误处理

`Parse` 返回两类错误之一：

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

## 批量操作

并发解析多个向量时，使用包级别的批量辅助函数：

```go
type BatchParseResult struct {
    Index  int          // 原始输入索引
    Vector *cvss.Cvss3x // 失败时为 nil
    Error  error        // 成功时为 nil
}

func BatchParse(vectors []string, workerCount int) []BatchParseResult

type BatchValidateResult struct {
    Index  int
    Vector *cvss.Cvss3x
    Valid  bool
    Errors []string
    Error  error
}

func BatchValidate(vectors []string, workerCount int) []BatchValidateResult
```

`workerCount <= 0` 时使用 `len(vectors)` 个 worker。结果按输入顺序返回。

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
    "not-a-vector",
}, 4)
for _, r := range results {
    if r.Error != nil {
        fmt.Printf("索引 %d 失败: %v\n", r.Index, r.Error)
        continue
    }
    fmt.Printf("索引 %d: %s\n", r.Index, r.Vector.String())
}
```

## 支持的向量格式

### CVSS 3.0 / 3.1

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

## 使用示例

### 基本解析

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatalf("解析失败: %v", err)
    }

    fmt.Printf("原始向量: %s\n", vectorStr)
    fmt.Printf("解析结果: %s\n", vector.String())
    fmt.Printf("版本:     %d.%d\n", vector.MajorVersion, vector.MinorVersion)
}
```

### 批量解析

```go
func parseBatch(vectors []string) {
    results := parser.BatchParse(vectors, 4)
    for _, r := range results {
        if r.Error != nil {
            fmt.Printf("向量 %d 解析失败: %v\n", r.Index+1, r.Error)
            continue
        }
        fmt.Printf("向量 %d: %s -> 解析成功\n", r.Index+1, r.Vector.String())
    }
}
```

### 容错解析（无前缀）

当输入可能缺少 `CVSS:3.1/` 前缀时，使用 `ParseRelaxed`：

```go
// 接受 "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" —— 假定为 3.1
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
if err != nil {
    log.Fatal(err)
}
fmt.Println(cv.String()) // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### 解析并验证（拒绝不完整向量）

```go
cv, err := parser.ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
if err != nil {
    // 可能是解析错误，也可能是列出缺失指标的 cvss.ValidationErrors
    log.Fatal(err)
}
fmt.Println(cv.String())
```

## 性能优化

### 并发解析

`Cvss3xParser` 持有可变游标状态，**不可**跨 goroutine 共享同一实例。每个向量构造新的解析器（或使用 `BatchParse`，它已为你处理）：

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

### 1. 输入验证

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

### 2. 日志记录

```go
func parseWithLogging(vectorStr string) (*cvss.Cvss3x, error) {
    start := time.Now()
    defer func() {
        log.Printf("解析耗时: %v", time.Since(start))
    }()

    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        log.Printf("解析失败 '%s': %v", vectorStr, err)
        return nil, err
    }
    log.Printf("解析成功 '%s'", vectorStr)
    return cv, nil
}
```

## 相关文档

- [parser 包概述](/zh/api/parser/)
- [Cvss3x 数据结构](/zh/api/cvss/cvss3x)
- [错误处理指南](/zh/api/cvss/)
- [解析示例](/zh/examples/parsing)
