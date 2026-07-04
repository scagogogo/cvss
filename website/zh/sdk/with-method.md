---
title: With-Method 不可变 Setter
description: cvss.Cvss3x.WithAVMethod ... WithMAMethod / WithVersionMethod / WithTemporalMethod——可链式、不可变的逐指标 setter，返回修改副本，绝不修改接收者。
---

# 🛠️ With-Method 不可变 Setter

🛠️ 功能点 · `pkg/cvss`

`With*Method` 系列是 `SetMetricValue` 的不可变对应物：每次调用返回接收者的**修改副本**，改动一个指标（或一组），原对象不变。由于每个方法都接收并返回 `*Cvss3x`，自然可链式调用，形成流畅的写时复制编辑风格。

## 简介

```go
step1, err := cv.WithAVMethod('L')      // 副本上 AV:N -> AV:L
modified, err := step1.WithSMethod('C') // 该副本上 S:U -> S:C
```

每个 `With<指标>Method(val rune)` 用对应的 `vector.Get*` 工厂校验 `val`，失败时返回包装为 `<短名>: <原因>` 的错误。设置 Temporal 或 Environmental 指标时，返回副本上对应子结构会被惰性分配（与 `SetMetricValue` 一致）。

## 工作原理

每个 `With*Method` 形状一致：nil 检查 → 工厂查找 → `Clone` → 在副本上写字段 → 返回副本。`WithTemporalMethod` 链式调用 `WithE/RL/RC`；环境组的 setter 先分配子结构。接收者永不被写入，故链式调用可安全组合。

```mermaid
flowchart TD
    CV[📦 *Cvss3x receiver] --> Nil{"🟡 nil?"}
    Nil -- yes --> NErr("[🔴 ErrNilReceiver]")
    Nil -- no --> Fac[🔍 vector.Get* value]
    Fac -- error --> FErr("[\"🔴 wrapped \\"NAME: cause\\"\"]")
    Fac -- ok --> Clone[🟢 Clone receiver]
    Clone --> Group{"🟡 Temporal/Env field?"}
    Group -- yes --> Alloc[🟣 lazy-allocate sub-struct]
    Group -- no --> Write
    Alloc --> Write[✏️ set field on clone]
    Write --> Out("[✅ modified *Cvss3x\nreceiver unchanged]")

    Out --> Chain["🔗 .WithSMethod('C') repeats"]
    Chain --> CV2[📦 previous copy]

    CV -.compare.-> Set["SetMetricValue: same clone-and-write\nbut resolves by shortName string"]
```

## 接口参考

### 基础指标 setter

```go
func (x *Cvss3x) WithAVMethod(val rune) (*Cvss3x, error)  // Attack Vector
func (x *Cvss3x) WithACMethod(val rune) (*Cvss3x, error)  // Attack Complexity
func (x *Cvss3x) WithPRMethod(val rune) (*Cvss3x, error)  // Privileges Required
func (x *Cvss3x) WithUIMethod(val rune) (*Cvss3x, error)  // User Interaction
func (x *Cvss3x) WithSMethod(val rune) (*Cvss3x, error)   // Scope
func (x *Cvss3x) WithCMethod(val rune) (*Cvss3x, error)   // Confidentiality
func (x *Cvss3x) WithIMethod(val rune) (*Cvss3x, error)   // Integrity
func (x *Cvss3x) WithAMethod(val rune) (*Cvss3x, error)   // Availability
```

每个克隆接收者（`x.Clone()`），在副本上设置字段并返回。nil 接收者返回 `(nil, ErrNilReceiver)`。

### 时间指标 setter

```go
func (x *Cvss3x) WithEMethod(val rune) (*Cvss3x, error)   // Exploit Code Maturity
func (x *Cvss3x) WithRLMethod(val rune) (*Cvss3x, error)  // Remediation Level
func (x *Cvss3x) WithRCMethod(val rune) (*Cvss3x, error)  // Report Confidence

func (x *Cvss3x) WithTemporalMethod(e, rl, rc rune) (*Cvss3x, error)
```

单值版本在副本的 `Cvss3xTemporal` 为 nil 时惰性分配。`WithTemporalMethod` 一次设置全部三个时间指标，内部链式调用 `WithEMethod` -> `WithRLMethod` -> `WithRCMethod`，遇首个错误即短路返回。

### 环境指标 setter

```go
func (x *Cvss3x) WithCRMethod(val rune) (*Cvss3x, error)  // Confidentiality Requirement
func (x *Cvss3x) WithIRMethod(val rune) (*Cvss3x, error)  // Integrity Requirement
func (x *Cvss3x) WithARMethod(val rune) (*Cvss3x, error)  // Availability Requirement
func (x *Cvss3x) WithMAVMethod(val rune) (*Cvss3x, error) // Modified Attack Vector
func (x *Cvss3x) WithMACMethod(val rune) (*Cvss3x, error) // Modified Attack Complexity
func (x *Cvss3x) WithMPRMethod(val rune) (*Cvss3x, error) // Modified Privileges Required
func (x *Cvss3x) WithMUIMethod(val rune) (*Cvss3x, error) // Modified User Interaction
func (x *Cvss3x) WithMSMethod(val rune) (*Cvss3x, error)  // Modified Scope
func (x *Cvss3x) WithMCMethod(val rune) (*Cvss3x, error)  // Modified Confidentiality
func (x *Cvss3x) WithMIMethod(val rune) (*Cvss3x, error)  // Modified Integrity
func (x *Cvss3x) WithMAMethod(val rune) (*Cvss3x, error)  // Modified Availability
```

每个在副本的 `Cvss3xEnvironmental` 为 nil 时惰性分配。

### 版本 setter

```go
func (x *Cvss3x) WithVersionMethod(major, minor int) (*Cvss3x, error)
```

返回修改版本号的副本。与 `ConvertToVersion` 不同，它**不**校验版本是否为 3.0 或 3.1——只设置字段。需要校验时请用 `ConvertToVersion`。

::: tip With*Method 与 SetMetricValue 与 ConvertToVersion
`SetMetricValue("AV", 'L')` 与 `WithAVMethod('L')` 职责相同；前者泛型（指标名为字符串），后者类型化且可链式。`WithVersionMethod` 是原始版本 setter；`ConvertToVersion` 增加版本校验，是安全默认。
:::

::: warning 错误会打断链
由于每个方法返回 `(*Cvss3x, error)`，不重新赋值就无法越过错误继续链。惯用模式是在链末检查错误（或用 `Must*` 风格辅助）——链中错误只有在逐步重新赋值时，才会保留上一步成功的部分结果。
:::

## 示例

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if err != nil {
        panic(err)
    }

    // 链式不可变编辑；原对象不变。
    step1, err := cv.WithAVMethod('L') // 副本上 AV:N -> AV:L
    if err != nil {
        panic(err)
    }
    harder, err := step1.WithSMethod('C') // 该副本上 S:U -> S:C
    if err != nil {
        panic(err)
    }
    fmt.Println(cv.String())      // 仍是 .../AV:N/.../S:U/...
    fmt.Println(harder.String())  // .../AV:L/.../S:C/...

    // 一次调用添加完整时间组。
    withTemp, err := cv.WithTemporalMethod('F', 'U', 'C')
    if err != nil {
        panic(err)
    }
    fmt.Println(withTemp.HasTemporalMetrics()) // true

    // 添加修改的环境指标；该组惰性分配。
    withEnv, err := cv.WithMAMethod('L')
    if err != nil {
        panic(err)
    }
    fmt.Println(withEnv.HasEnvironmentalMetrics()) // true

    // 非法值以包装错误形式返回。
    _, err = cv.WithAVMethod('Q')
    fmt.Println(err) // AV: unknown attack vector value: Q

    // 原始版本变更（不校验）对比 ConvertToVersion（校验）。
    raw, _ := cv.WithVersionMethod(3, 0)
    fmt.Println(raw.Version()) // 3.0
}
```

## 相关

- [指标读写器](/zh/sdk/accessor) —— 与之对应的字符串键 `GetMetricValue` / `SetMetricValue`
- [版本转换](/zh/sdk/conversion) —— `ConvertToVersion` 与原始 `WithVersionMethod` 对比
- [便捷方法](/zh/sdk/convenience) —— 每个 `With*Method` 调用所依赖的 `Clone`
- [Builder 构建器](/zh/sdk/builder) —— 可变的流式构造对应物
- CLI：[`modify`](/zh/cli/commands/modify)
