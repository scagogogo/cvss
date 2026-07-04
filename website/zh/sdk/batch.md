---
title: 批量评分
description: cvss.BatchScore / BatchAllScores——用 worker 池并发评分多个 CVSS 向量；workerCount 控制并发，<=0 时取 len(vectors)。
---

# ⚡ 批量评分

⚡ 功能点 · `pkg/cvss`

`BatchScore` 与 `BatchAllScores` 使用固定大小的 worker 池对 `*Cvss3x` 切片运行 CVSS 评分流水线。每个结果都携带原始索引，调用方可以将输入与输出对齐；`Error` 字段确保单个坏向量不会中断整批。

## 简介

```go
results := cvss.BatchScore([]*cvss.Cvss3x{a, b, c}, 4)
for _, r := range results {
    if r.Error != nil {
        log.Printf("index %d: %v", r.Index, r.Error)
        continue
    }
    fmt.Printf("index %d: %.1f (%s)\n", r.Index, r.Score, r.Severity)
}
```

`workerCount` 控制并发。`workerCount <= 0` 时取 `len(vectors)`，超过切片长度的值会被钳制为 `len(vectors)`。输入切片中的 `nil` 元素会产生 `Error = ErrNilReceiver` 的结果，而非 panic。结果按输入顺序返回——goroutine 写入 `results[idx]`，而不是追加到共享目标。

## 接口参考

### BatchScore

```go
func BatchScore(vectors []*Cvss3x, workerCount int) []BatchScoreResult
```

用 `NewCalculator(v).Calculate()` 为每个向量评分，并以 `GetSeverity(score)` 标注严重性。空输入返回 `nil`。

```go
results := cvss.BatchScore(vectors, 0) // 0 => len(vectors) 个 worker
```

### BatchScoreResult

```go
type BatchScoreResult struct {
    Index    int       // 原始输入索引
    Vector   *Cvss3x   // 原始 CVSS 对象（输入为 nil 时为 nil）
    Score    float64   // 评分，失败时为 0
    Severity Severity  // 严重性等级
    Error    error     // 评分错误，成功时为 nil
}
```

### BatchAllScores

```go
func BatchAllScores(vectors []*Cvss3x, workerCount int) []BatchAllScoresResult
```

通过 `Calculator.GetAllScores` 为每个向量计算完整的 `*AllScores`（基础/时间/环境 + 子评分）。当不止需要主分数时使用。

```go
all := cvss.BatchAllScores(vectors, 4)
```

### BatchAllScoresResult

```go
type BatchAllScoresResult struct {
    Index  int        // 原始输入索引
    Scores *AllScores // 全量评分，失败时为 nil
    Error  error      // 错误
}
```

::: tip Index 是关联键
函数从不重排或丢弃结果。`results[i].Index` 始终等于输入切片中的位置，无需排序即可将失败关联回源向量。
:::

::: warning workerCount 是上限，不保证池大小
池大小为 `min(workerCount, len(vectors))`。对 5 元素切片传 `1000` 只会起 5 个 goroutine，而非 1000。
:::

## 并发模型

```mermaid
flowchart LR
    subgraph Producer
        J[jobs 通道<br/>索引 0..N-1]
    end
    subgraph Workers[workerCount 个 goroutine]
        W1[worker 1]
        W2[worker 2]
        W3[worker ...]
    end
    subgraph Sink
        R[results[idx]<br/>按索引写入]
    end
    J --> W1 & W2 & W3
    W1 --> R
    W2 --> R
    W3 --> R
```

一个容量为 `len(vectors)` 的缓冲 `jobs` 通道将索引分发给 `workerCount` 个 goroutine。每个 worker 取一个索引，对 `vectors[idx]` 评分，直接写入 `results[idx]`——没有结果通道、不会重排。`sync.WaitGroup` 控制返回。

## 示例

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectors := []*cvss.Cvss3x{
        mustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        mustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        nil, // nil 条目会被报告，而非 panic
        mustParse("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"),
    }

    results := cvss.BatchScore(vectors, 4)
    for _, r := range results {
        if r.Error != nil {
            log.Printf("index %d 失败: %v", r.Index, r.Error)
            continue
        }
        fmt.Printf("index %d: %.1f (%s)\n", r.Index, r.Score, r.Severity)
    }

    // 一次性为每个向量取全量评分。
    for _, r := range cvss.BatchAllScores(vectors, 2) {
        if r.Error != nil {
            continue
        }
        fmt.Printf("index %d base=%.1f\n", r.Index, r.Scores.BaseScore)
    }
}

func mustParse(s string) *cvss.Cvss3x {
    cv, err := parser.ParseString(s)
    if err != nil {
        panic(err)
    }
    return cv
}
```

## 相关

- [评分计算器](/zh/sdk/calculator) —— `BatchScore` 底层调用
- [评分](/zh/sdk/scores) —— `BatchAllScores` 产出的逐向量 `AllScores`
- [严重性](/zh/sdk/severity) —— 每个结果的 `Severity` 字段
- CLI：[`batch score`](/zh/cli/commands/batch-score)
