---
title: 构建向量
description: 用 Go SDK 的三种方式构建同一个 CVSS v3.1 向量——FromMap、流式 Builder、函数式 Options——并学会各自适用场景。
---

# 🏗️ 构建向量

⏱️ 15 分钟 · 中级 · Go SDK

当向量字符串已经存在时，用 `parser.ParseString` 解析是对的。但当你的代码*计算*出一个向量——从扫描器、表单或数据库行组装指标——你需要编程构建。Go SDK 给你三种惯用法，都产出同一个向量。本教程用三种方式构建 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 并对比。

## 前置条件

- Go 1.18+（模块的 `go.mod` 锁定 `go 1.18`）
- 学完 [getting-started](./getting-started)，熟悉 SDK 导入路径
- 本地有模块：`go get github.com/scagogogo/cvss-skills`

## 流程

```mermaid
flowchart LR
  T[🎯 target<br/>CVSS:3.1/AV:N/.../A:H → 9.8] --> CH{input shape?}
  CH -- map / JSON / DB row --> F[⚙️ FromMap<br/>map[string]string]
  CH -- fixed, readable --> B[⚙️ NewBuilder<br/>fluent .AV().Build]
  CH -- dynamic call site --> O[⚙️ NewCvss3xWithOptions<br/>WithXxx opts...]
  F --> CV[🔤 *Cvss3x]
  B --> CV
  O --> CV
  CV --> CA[🧮 NewCalculator.Calculate]
  CA --> R[✅ 9.8 Critical<br/>identical downstream]
  CV -.-> |ToMap / FromVectorValues| RT[↩️ round-trip helpers]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class T in
  class CH branch
  class F,B,O,CV,CA step
  class R,RT out
```

## 目标

下面每个示例都构建这个向量并喂给计算器：

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   →  9.8 Critical
```

## 第 1 步 —— `cvss.FromMap`：数据形状的输入

`FromMap` 接受 `map[string]string`，key 是指标短名（`AV`、`AC`、…），value 是短值（`N`、`L`、…）。`version` 键（或 `WithVersion` option）设置规范版本。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	m := map[string]string{
		"version": "3.1",
		"AV": "N", "AC": "L", "PR": "N", "UI": "N",
		"S": "U", "C": "H", "I": "H", "A": "H",
	}
	cv, err := cvss.FromMap(m)
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

::: tip FromMap 适合数据本就是 map 的场景
如果你的输入来自 JSON、数据库行或表单的 `map[string]string`，`FromMap` 是最低摩擦的路径——无需链式、无需 builder 管道。`MustFromMap(m)` 是出错即 panic 的变体，适合测试。
:::

## 第 2 步 —— `cvss.NewBuilder()`：流式链式

Builder 是流式 API：每个方法返回 builder 本身，所以你在一个表达式里链式调用。方法接收 `rune` 值（`'N'`、`'L'`、…），每个指标一个方法。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	cv, err := cvss.NewBuilder().
		Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').
		S('U').C('H').I('H').A('H').
		Build()
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

builder 也有时间和环境方法（`E`、`RL`、`RC`、`CR`、`MAV`、…），链式形状一致。`Build()` 返回结构和错误；`MustBuild()` 出错即 panic。

::: tip Builder 适合固定、可读的向量
当向量在写代码时就固定（预设、测试夹具、文档化的默认值），builder 自上而下读，便于视觉审计。
:::

## 第 3 步 —— `cvss.NewCvss3xWithOptions`：函数式选项

函数式选项惯用法把 `WithXxx(rune)` 选项传给变参构造器。每个指标有一个 `WithXxx` option（`WithAV`、`WithAC`、…），`WithVersion31()` / `WithVersion30()` 设置版本。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	cv, err := cvss.NewCvss3xWithOptions(
		cvss.WithVersion31(),
		cvss.WithAV('N'), cvss.WithAC('L'), cvss.WithPR('N'), cvss.WithUI('N'),
		cvss.WithS('U'), cvss.WithC('H'), cvss.WithI('H'), cvss.WithA('H'),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(cv.String())
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

	calc := cvss.NewCalculator(cv)
	score, _ := calc.Calculate()
	fmt.Printf("%.1f\n", score) // 9.8
}
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8
```

::: tip Options 适合调用点动态变化的场景
函数式选项在指标集合动态时大放异彩——扫描器按条件发时间指标、配置结构映射到选项。你可以把 `WithXxx` 追加到切片再展开：`cvss.NewCvss3xWithOptions(opts...)`。新增选项不破坏已有调用方。
:::

还有一次性设置一组的便捷选项：

- `WithTemporal(e, rl, rc rune)` —— 一次调三个时间指标。
- `WithRequirements(cr, ir, ar rune)` —— 一次调三个需求指标。

## 第 4 步 —— 三种风格对比

| 惯用法 | 输入形状 | 适合 | 变体 |
| --- | --- | --- | --- |
| `FromMap(map[string]string)` | map | JSON / 数据库行 / 表单 | `MustFromMap`（panic） |
| `NewBuilder().AV(...).Build()` | 链式调用 | 固定、可读向量、测试夹具 | `BuildChecked`、`MustBuild` |
| `NewCvss3xWithOptions(opts...)` | 选项切片 | 动态调用点、库 API | `MustNewCvss3xWithOptions`（panic） |

三者产出同一个 `*Cvss3x`，下游的计算器、序列化器、比较器行为完全一致。两两字符串相等可证：

```go
// a := FromMap(...), b := NewBuilder()...Build(), c := NewCvss3xWithOptions(...)
a.String() == b.String() // true
b.String() == c.String() // true
```

::: warning 一个代码库选一种惯用法
三种惯用法在类型层面可互换，但混用会让代码更难扫读。选匹配你输入形状的那一种并坚持。
:::

## 第 5 步 —— 往返：`ToMap` 与 `FromVectorValues`

另两个构造助手补全工具箱：

`ToMap()` 是 `FromMap` 的逆操作——把 `Cvss3x` 序列化回 `map[string]string`：

```go
cv, _ := cvss.NewBuilder().Version(3, 1).
	AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').Build()
m := cv.ToMap()
// map[A:H AC:L AV:N C:H I:H PR:N S:U UI:N version:3.1]
```

`FromVectorValues(version string, pairs ...string)` 从 `"KEY:VALUE"` 对构建：

```go
cv, err := cvss.FromVectorValues("3.1",
	"AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H")
```

当你已有拆分好的段（例如来自分词器）但没有完整向量串时，用 `FromVectorValues`。

## 小结

- **`FromMap`** —— 适合 map 形状数据（JSON、数据库、表单）。
- **`NewBuilder()`** —— 适合固定、可读、链式构造。
- **`NewCvss3xWithOptions`** —— 适合动态调用点和库 API。
- 三者返回同一个 `*Cvss3x`；下游（计算器、`String()`、`ToMap()`）完全一致。
- `MustFromMap` / `MustBuild` / `MustNewCvss3xWithOptions` 出错即 panic——仅供测试。

## 下一步

- 在 [version-migration](./version-migration) 中在 v3.0 与 v3.1 之间迁移
- 在 [presets-and-random](./presets-and-random) 中用 `mock.RandomCvss3x` 生成测试向量
