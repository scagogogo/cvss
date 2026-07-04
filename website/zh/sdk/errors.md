---
title: 哨兵错误
description: pkg/cvss/errors.go 导出的四个哨兵错误——ErrNilReceiver、ErrIncompleteBaseMetrics、ErrUnsupportedVersion、ErrInvalidMetricValue，用于 errors.Is 比对。
---

# 🚨 哨兵错误

`pkg/cvss/errors.go` · 4 个导出哨兵错误

> 结构化校验错误（`ValidationError` / `ValidationErrors`）定义在 `pkg/cvss/validate.go`，文档见 [/zh/sdk/validation](/zh/sdk/validation)。本页只讲 `errors.go` 中声明的四个哨兵错误。

## 简介

`errors.go` 声明了四个包级哨兵错误变量，方便调用方用 `errors.Is` 比对而非字符串匹配。`ErrNilReceiver` 在 SDK 多处被返回（`pkg/cvss/with_method.go` 中的 `With*` 链式方法，以及 `batch.go`、`score_range.go`、`accessor.go`、`conversion.go`、`impact.go`）。其余三个——`ErrIncompleteBaseMetrics`、`ErrUnsupportedVersion`、`ErrInvalidMetricValue`——作为稳定哨兵导出供调用方使用/比对；注意 SDK 自身的 `Check()` 与 `Calculator` 当前对等价条件是用 `fmt.Errorf` 字符串上报的，并未包装这些哨兵，因此对这些代码路径用 `errors.Is` 不会命中。它们面向应用层错误分类，或供希望返回规范 CVSS 错误的代码使用。

```go
err := cv.WithAVMethod('N') // cv 为 nil 时
if errors.Is(err, cvss.ErrNilReceiver) {
    // 处理 nil 接收者
}
```

## 工作原理

这四个哨兵值是供 `errors.Is` 匹配的稳定值。`ErrNilReceiver` 由 SDK 中各 nil 守卫方法直接返回；其余三个作为规范分类器导出——应用代码可包装/返回它们，而 SDK 自身的 `Check()`/`Calculator` 路径以 `fmt.Errorf` 字符串报告等价状况，**并不**包装这些哨兵。

```mermaid
flowchart TD
    Call[📞 method call] --> Nil{"🟡 receiver nil?"}
    Nil -- yes --> ENR[🔴 ErrNilReceiver]
    Nil -- no --> Src{"🟡 input kind?"}

    Src -- nil receiver only<br/>With*/accessor/batch/score_range --> ENR

    Src -- version not 3.0/3.1 --> EUV["🔴 ErrUnsupportedVersion<br/>canonical classifier"]
    Src -- base metric missing --> EIBM["🔴 ErrIncompleteBaseMetrics<br/>canonical classifier"]
    Src -- invalid metric value --> EIMV["🔴 ErrInvalidMetricValue<br/>canonical classifier"]

    note1["ℹ️ Check()/Calculator report these<br/>conditions via fmt.Errorf strings,<br/>NOT wrapping the sentinels"] -.-> Src

    ENR --> Match["errors.Is(err, sentinel)"]
    EUV --> Match
    EIBM --> Match
    EIMV --> Match
    Match --> Handle("[\"✅ classify & handle\"]")
```

## 接口参考

```go
var (
    ErrNilReceiver          = errors.New("nil receiver")
    ErrIncompleteBaseMetrics = errors.New("incomplete base metrics")
    ErrUnsupportedVersion   = errors.New("unsupported CVSS version")
    ErrInvalidMetricValue   = errors.New("invalid metric value")
)
```

| 哨兵 | `Error()` 文本 | 含义 |
| --- | --- | --- |
| `ErrNilReceiver` | `nil receiver` | 方法在 `nil` 的 `*Cvss3x`（或 nil 子接收者）上被调用。**由** `With*` 链式方法、批量助手、`GetScoreRange`、accessor、conversion、impact 等在接收者为 nil 时返回。 |
| `ErrIncompleteBaseMetrics` | `incomplete base metrics` | 基础指标未完整填充。作为规范哨兵导出；SDK 自身的 `Check()` 对同一条件用 `fmt.Errorf` 字符串上报，仅当你的代码返回/包装此值时才用哨兵比对。 |
| `ErrUnsupportedVersion` | `unsupported CVSS version` | CVSS 版本不受支持（仅支持 3.0 与 3.1）。作为规范哨兵导出；`Cvss3x.Check()` 对同一条件用 `fmt.Errorf` 上报。 |
| `ErrInvalidMetricValue` | `invalid metric value` | 指标取值不在其类别合法范围内。作为规范哨兵导出，供应用层分类使用。 |

四个均为普通 `errors.New` 值——无包装，可安全用 `errors.Is` 比对。

## 示例

```go
package main

import (
	"errors"
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	var cv *cvss.Cvss3x // nil

	_, err := cv.WithAVMethod('N')
	switch {
	case errors.Is(err, cvss.ErrNilReceiver):
		fmt.Println("接收者为 nil，跳过")
	case errors.Is(err, cvss.ErrIncompleteBaseMetrics):
		fmt.Println("基础指标不完整")
	case errors.Is(err, cvss.ErrUnsupportedVersion):
		fmt.Println("不支持的版本")
	case errors.Is(err, cvss.ErrInvalidMetricValue):
		fmt.Println("指标取值非法")
	default:
		fmt.Println("其他错误:", err)
	}
}
```

## 相关

- [/zh/sdk/validation](/zh/sdk/validation) — `ValidationError` / `ValidationErrors` 与 `Check` / `Validate` 入口
- [/zh/sdk/cvss](/zh/sdk/cvss) — `Cvss3x` 类型，其方法返回这些哨兵
- [/zh/sdk/calculator](/zh/sdk/calculator) — 评分助手，会暴露 `ErrNilReceiver` / `ErrIncompleteBaseMetrics` 相关条件
