---
title: Map 与向量值构造
description: cvss.FromMap / MustFromMap / ToMap / FromVectorValues——从 map[string]string 或 key:value 对构造 Cvss3x（注意 "version" 键），并反向序列化为 map。
---

# 🗂️ Map 与向量值构造

🗂️ 功能点 · `pkg/cvss`

`FromMap` 与 `FromVectorValues` 从松散类型输入——`map[string]string` 或 `"AV:N"` 变参对——构造 `*Cvss3x`；`ToMap` 是其逆操作。它们是配置、CSV 行、CLI 标志等场景的粘合层，免去拼装完整向量字符串的麻烦。

## 简介

```go
cv, err := cvss.FromMap(map[string]string{
    "version": "3.1",
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "H", "I": "H", "A": "H",
    "E": "F", "RL": "T",
})
// 或：cvss.FromVectorValues("3.1", "AV:N", "AC:L", ...)
m := cv.ToMap() // 往返回 map
```

## 工作原理

`FromMap` 把 `version` 键解析为 `Major/MinorVersion`，随后迭代其余条目，经 `mapKeyValueToStruct`（内部调用 `vector.GetVectorByShortName`）逐个派发；逐键错误被累积并一并返回。`FromVectorValues` 在冒号处拆分每个 `"KEY:VALUE"` 对。`ToMap` 遍历三个子结构，仅输出非 nil 指标加 `version`。

```mermaid
flowchart TD
    Map[🟦 map string string + version key] --> FromMap
    Pairs["🟦 \"AV:N\",\"AC:L\",... variadic"] --> FromVV["FromVectorValues(version, pairs...)"]

    FromMap --> ParseVer[🔢 parseVersionString]
    ParseVer -- error --> VErr("[🔴 invalid version]")
    ParseVer -- ok --> Init[🟣 init *Cvss3x 3.x]

    FromVV --> Split["✂️ splitKeyValue at ':'"]
    Split -- error --> SErr("[🔴 missing colon]")
    Split -- ok --> Init

    Init --> Loop["🔄 each key:value"]
    Loop --> MapKV[🗺️ mapKeyValueToStruct]
    MapKV --> Fac[🔍 vector.GetVectorByShortName]
    Fac -- error --> Acc[📋 accumulate error]
    Fac -- ok --> Set[✏️ set field, lazy-allocate sub-struct]
    Set --> Loop
    Acc --> Loop
    Loop --> Done{"🟡 any errors?"}
    Done -- yes --> FErr("[🔴 FromMap errors]")
    Done -- no --> FOk("[✅ *Cvss3x]")

    FOk --> ToMap["ToMap (inverse)"]
    ToMap --> Walk["🔄 walk Base/Temporal/Environmental"]
    Walk --> Emit[🟢 emit non-nil metrics + version]
    Emit --> MOut("[✅ map string string]")
```

## 接口参考

### FromMap

```go
func FromMap(m map[string]string) (*Cvss3x, error)
```

从短名/短值对构造 `*Cvss3x`。`"version"` 键（值为 `"3.0"` 或 `"3.1"`）设置版本；缺省时默认 v3.1。其它键必须是合法的指标短名且短值有效；`FromMap` 收集**所有**错误并以单个包装错误返回（`FromMap errors: [...]`）。`nil` map 返回 `map is nil`。

```go
cv, err := cvss.FromMap(map[string]string{"version": "3.1", "AV": "N", "AC": "L"})
```

::: tip "version" 键是特殊的
它是唯一的非指标键。其余键都会分派给对应的 `vector.Get*` 工厂，因此 `"XX"` 这类未知键或 `"AV": "Q"` 这类非法值都会进入错误列表。
:::

### MustFromMap

```go
func MustFromMap(m map[string]string) *Cvss3x
```

包装 `FromMap`，出错即 panic。用于编译期已知的 map，其中坏条目属于程序员错误。

```go
cv := cvss.MustFromMap(map[string]string{"version": "3.1", "AV": "N", /* ... */})
```

### ToMap

```go
func (x *Cvss3x) ToMap() map[string]string
```

`FromMap` 的逆操作。返回含 `"version"` 键及每个**已设**指标一项（短名 -> 短值）的 map。未设置的指标被省略。nil 接收者返回 `nil`。注意：`FromMap(ToMap(x))` 可无损往返，因为两侧只携带已设指标。

```go
m := cv.ToMap() // {"version":"3.1", "AV":"N", "AC":"L", ...}
```

### FromVectorValues

```go
func FromVectorValues(version string, pairs ...string) (*Cvss3x, error)
```

第一个参数为版本，随后为 `"KEY:VALUE"` 变参对。每个对必须含冒号；缺失冒号返回 `invalid pair "AVN": missing colon separator`。与 `FromMap` 不同，此函数在**第一个**错误处返回（不聚合）。至少需要一个对。

```go
cv, err := cvss.FromVectorValues("3.1", "AV:N", "AC:L", "PR:N", "UI:N",
    "S:U", "C:H", "I:H", "A:H")
```

::: warning FromMap 聚合，FromVectorValues 快速失败
`FromMap` 收集所有错误一并报告；`FromVectorValues` 在第一个坏对处停止。按输入的失败模式选择——配置文件通常希望聚合，标志解析通常希望快速失败。
:::

## 示例

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
    // 从 map 构造（例如解析后的配置行）。
    cv, err := cvss.FromMap(map[string]string{
        "version": "3.1",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
        "E": "F", "RL": "T", "RC": "C",
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(cv.String())

    // 往返回 map；仅出现已设指标。
    m := cv.ToMap()
    fmt.Println(m["AV"], m["E"]) // N F
    fmt.Println(m["version"])     // 3.1

    // FromVectorValues：版本在前，随后 "KEY:VALUE" 对。
    cv2, err := cvss.FromVectorValues("3.1",
        "AV:N", "AC:L", "PR:N", "UI:N",
        "S:U", "C:H", "I:H", "A:H")
    if err != nil {
        panic(err)
    }
    fmt.Println(cv2.HasTemporalMetrics()) // false——无 E/RL/RC

    // MustFromMap 在坏值时 panic——适合字面量。
    func() {
        defer func() { recover() }()
        cvss.MustFromMap(map[string]string{"version": "3.1", "AV": "Q"})
    }()

    // FromMap 将所有错误聚合为一条消息。
    _, err = cvss.FromMap(map[string]string{
        "version": "3.1", "AV": "Q", "AC": "Z",
    })
    fmt.Println(err) // FromMap errors: [AV=Q: ... AC=Z: ...]
}
```

## 相关

- [指标读写器](/zh/sdk/accessor) —— 单指标读写的 `GetMetricValue` / `SetMetricValue`
- [Builder 构建器](/zh/sdk/builder) —— 类型化的流式构造替代方案
- [pkg/vector](/zh/sdk/vector) —— 校验每个值的 `Get*` 工厂
- CLI：[`map`](/zh/cli/commands/map)
