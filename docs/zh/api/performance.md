# 性能 API 参考

本文档涵盖 CVSS Skills 中与性能相关的 API 和模式：`pkg/parser` 中的并发批量辅助函数、解析器/计算器的开销模型，以及如何用 Go 标准库做基准测试。

## 概述

CVSS Skills **不**提供自定义的基准测试器、对象池或缓存类型——这些关注点留给你的应用层。库*提供*的是：

- **并发批量辅助函数**（`pkg/parser`）—— `BatchParse` 和 `BatchValidate` 为你运行 worker goroutine。
- **低成本的按调用构造** —— `Cvss3xParser` 和 `Calculator` 在构造时绑定输入，不在向量间复用，因此既无可借用的池，也无需池。
- **一步到位的便捷函数** —— `ParseString`、`ParseAndValidate`、`ParseAndScore` 等把多步流程合并为一次调用。

基准测试与性能分析请使用 Go 标准库的 `testing.B` 和 `runtime/pprof` —— 见下文[基准测试](#基准测试)。

## 开销模型

理解每个对象绑定什么，是写出高性能代码的关键：

| 对象 | 绑定输入时机 | 可复用？ | 线程安全？ |
| ---- | ----------- | ------- | --------- |
| `parser.Cvss3xParser` | 构造时（`NewCvss3xParser(str)`） | 否——没有 `SetVector`；每个向量构造一个新解析器 | 解析器不在 goroutine 间共享 |
| `cvss.Calculator` | 构造时（`NewCalculator(cv)`） | 否——绑定一个 `*Cvss3x` | 计算器不在 goroutine 间共享 |
| `*cvss.Cvss3x` | 解析时 | 解析后只读；**可安全共享**用于并发读 | 是（只读） |

::: tip 没有 `SetVector`，也就没有池
由于 `Cvss3xParser` 在构造函数中绑定输入字符串且无法重绑，“解析器池”毫无收益——你仍然要为每个向量构造新解析器。`Calculator` 同理，它在构造时绑定一个 `*Cvss3x`。惯用模式就是按输入调用 `parser.ParseString(v)`；每次调用都构建一个短命、低开销的解析器。
:::

相比之下，解析出的 `*Cvss3x` 在成功解析后不可变，可安全地交给多个 goroutine 做只读访问（评分、比较、JSON 序列化）。

## 批量辅助函数

`pkg/parser` 包提供两个用于批量处理的并发辅助函数。两者都会启动固定数量的 worker 池、在结果中保持输入顺序，并收集每个输入的错误。

### BatchParse

```go
func BatchParse(vectors []string, workerCount int) []BatchParseResult
```

并发解析一组 CVSS 向量字符串。`workerCount` 控制 goroutine 数量；若 `workerCount <= 0`，默认为 `len(vectors)`；若超过输入长度，则被钳制下降。输入为空时返回 `nil`。

**参数：**
- `vectors`：待解析的 CVSS 向量字符串
- `workerCount`：worker goroutine 数量（钳制到 `len(vectors)`）

**返回：**
- `[]BatchParseResult`：每个输入一个结果，按输入顺序

**类型：**

```go
type BatchParseResult struct {
    Index  int          // 原始输入索引
    Vector *cvss.Cvss3x // 解析后的对象，失败时为 nil
    Error  error        // 解析错误，成功时为 nil
}
```

**示例：**

```go
results := parser.BatchParse([]string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
}, 4)
for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: %v", r.Index, r.Error)
        continue
    }
    fmt.Println(r.Vector.String())
}
```

### BatchValidate

```go
func BatchValidate(vectors []string, workerCount int) []BatchValidateResult
```

并发地解析**并**校验每个向量（内部使用 `ParseAndValidate`），一步完成。每个结果同时携带解析出的向量和一组校验错误消息。worker 数量钳制规则与 `BatchParse` 相同。

**参数：**
- `vectors`：待解析并校验的 CVSS 向量字符串
- `workerCount`：worker goroutine 数量

**返回：**
- `[]BatchValidateResult`：每个输入一个结果，按输入顺序

**类型：**

```go
type BatchValidateResult struct {
    Index  int          // 原始输入索引
    Vector *cvss.Cvss3x // 解析后的对象，失败时为 nil
    Valid  bool         // 向量是否有效
    Errors []string     // 所有校验错误消息
    Error  error        // 解析错误（区别于校验错误）
}
```

**示例：**

```go
results := parser.BatchValidate(myVectors, runtime.NumCPU())
valid := 0
for _, r := range results {
    if r.Valid {
        valid++
        continue
    }
    log.Printf("index %d invalid: %v", r.Index, r.Errors)
}
fmt.Printf("%d/%d valid\n", valid, len(results))
```

## 一步到位的便捷函数

对单个向量，`pkg/parser` 中的便捷函数把常见多步流程合并为一次调用。每个都是 `NewCvss3xParser` + `Parse` 的薄封装：

| 函数 | 返回 | 适用场景 |
| ---- | ---- | ------- |
| `ParseString(str)` | `(*Cvss3x, error)` | 只需解析后的结构体 |
| `MustParse(str)` | `*Cvss3x`（出错时 panic） | 测试 / 硬编码向量 |
| `ParseRelaxed(str, defaultVer)` | `(*Cvss3x, error)` | 输入可能缺少 `CVSS:` 前缀 |
| `ParseAndValidate(str)` | `(*Cvss3x, error)` | 需要结构化校验错误 |
| `ParseAndScore(str)` | `(*Cvss3x, float64, Severity, error)` | 一次调用完成 解析 → 校验 → 评分 |

常见“给我这个向量的分数”路径优先用 `ParseAndScore`——它免去手工构造 `Calculator` 的麻烦。

## 并发处理模式

当批量辅助函数不适用时（例如需要并行评分，或在工作流中扇出），惯用模式是用缓冲通道驱动 worker 池。由于解析后的 `*Cvss3x` 只读，可以安全地交给多个评分 goroutine：

```go
func scoreConcurrently(vectors []string, workers int) ([]float64, error) {
    type job struct{ idx int; vec string }
    type result struct{ idx int; score float64; err error }

    jobs := make(chan job, len(vectors))
    results := make([]float64, len(vectors))

    // 生产者
    go func() {
        for i, v := range vectors {
            jobs <- job{i, v}
        }
        close(jobs)
    }()

    // Worker —— 各自解析并评分自己的输入
    var wg sync.WaitGroup
    for w := 0; w < workers; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := range jobs {
                cv, err := parser.ParseString(j.vec)
                if err != nil {
                    // 视情况上报错误；此处存 0
                    continue
                }
                score, err := cvss.NewCalculator(cv).Calculate()
                if err == nil {
                    results[j.idx] = score
                }
            }
        }()
    }
    wg.Wait()
    return results, nil
}
```

::: warning 不要在 goroutine 间共享 `Calculator` 或 `Cvss3xParser`
`Calculator` 在构造时绑定一个 `*Cvss3x`，`Cvss3xParser` 绑定一个输入字符串。两者都是短命、单 goroutine 的。解析后的 `*Cvss3x` 是唯一可安全共享的对象——每个 goroutine 用 `cvss.NewCalculator(cv)` 构造一个新的 `Calculator`。
:::

## 基准测试

使用 Go 标准库的 `testing.B` 做基准测试——库内没有基准测试器。把基准测试放在 `_test.go` 文件中：

```go
func BenchmarkParseString(b *testing.B) {
    vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, _ = parser.ParseString(vector)
    }
}

func BenchmarkCalculate(b *testing.B) {
    cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = cvss.NewCalculator(cv).Calculate()
    }
}
```

运行：

```bash
go test -bench=. -benchmem ./...
```

CPU 和内存分析用 `runtime/pprof`（或 `go test` 的 `-cpuprofile` / `-memprofile` 标志）：

```bash
go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./...
go tool pprof cpu.prof
go tool pprof mem.prof
```

## 最佳实践

### 内存

1. **不要池化解析器/计算器** —— 它们在构造时绑定输入且无法重绑；按调用构造即可。
2. **复用解析后的 `*Cvss3x`** —— 解析后不可变；若同一向量被反复评分，可缓存它。
3. **基准测试中用 `b.ReportAllocs()`** —— 跟踪分配压力。
4. **大批量分批处理** —— 相比临时 worker 池，`BatchParse` / `BatchValidate` 避免了逐项 goroutine 启动开销。

### 并发

1. **选合理的 worker 数** —— CPU 密集的评分用 `runtime.NumCPU()` 作默认值。
2. **缓冲 jobs 通道** —— `make(chan job, len(inputs))` 防止生产者阻塞。
3. **保持输入顺序** —— 像 `BatchParse` 那样按索引写入结果，而不是追加。
4. **共享 `*Cvss3x`，不共享 `Calculator`** —— 解析后的结构体只读且并发安全；计算器不是。

### 缓存

1. **缓存解析后的向量，而非解析器** —— `*Cvss3x` 不可变且持有成本低。
2. **以规范化向量字符串为键** —— `cvss3x.String()` 返回规范形式；用它作缓存键。
3. **给缓存设上限** —— 无界 map 会无限增长；用 LRU（由你的应用选择库）。
4. **版本变更时失效** —— 指标相同的 `CVSS:3.0` 与 `CVSS:3.1` 向量评分可能不同；缓存键应含版本前缀。

## 示例

### 用 BatchParse 批量评分

```go
vectors := loadVectorsFromFile("vectors.txt") // []string，每行一个
results := parser.BatchParse(vectors, runtime.NumCPU())

for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: parse failed: %v", r.Index, r.Error)
        continue
    }
    score, err := cvss.NewCalculator(r.Vector).Calculate()
    if err != nil {
        log.Printf("index %d: score failed: %v", r.Index, err)
        continue
    }
    fmt.Printf("%s -> %.1f\n", r.Vector.String(), score)
}
```

### 缓存解析后的向量

```go
// 应用层 LRU 缓存；库不提供。
var cache = lru.New(capacity) // 来自你选择的 LRU 库

func scoreCached(vectorStr string) (float64, error) {
    if cv, ok := cache.Get(vectorStr); ok {
        return cvss.NewCalculator(cv.(*cvss.Cvss3x)).Calculate()
    }
    cv, err := parser.ParseString(vectorStr)
    if err != nil {
        return 0, err
    }
    cache.Add(vectorStr, cv)
    return cvss.NewCalculator(cv).Calculate()
}
```

## 相关文档

- [性能示例](/zh/examples/performance) - 实战优化走查
- [计算器 API](/zh/api/cvss/calculator) - 构造时绑定的评分 API
- [解析器 API](/zh/api/parser/) - `ParseString`、`BatchParse` 及便捷函数
