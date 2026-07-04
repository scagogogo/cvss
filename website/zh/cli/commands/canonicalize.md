---
title: canonicalize — 规范向量顺序
description: 将 CVSS 向量重排为规范指标顺序，并检查向量是否已是规范形态，支持 JSON 输出。
---

# 🔢 canonicalize

🔢 规范化 · 🟢 stable

## 简介

`cvss canonicalize` 把 CVSS 向量字符串重排为规范指标顺序（AV, AC, PR, UI, S, C, I, A, E, RL, RC, CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA）。使用 `--check` 可在不改写向量的前提下测试其是否已是规范形态。

## 工作原理

解析各指标并按固定的规范顺序重新输出；`--check` 跳过改写，只回答输入是否已是规范形式（退出码 0/1）。

```mermaid
flowchart TD
    V["💻 vector (any order)"]:::blue --> P["📦 parse"]:::blue
    P --> Mode{--check?}:::yellow
    Mode -- no --> Canon["Canonicalize<br/>reorder to AV,AC,PR,UI,S,<br/>C,I,A,E,RL,RC,CR,IR,AR,<br/>MAV,MAC,MPR,MUI,MS,MC,MI,MA"]:::blue
    Mode -- yes --> Cmp{already<br/>canonical?}:::yellow
    Canon --> Out(["📊 reordered vector"]):::green
    Cmp -- yes --> Yes(["✅ exit 0"]):::green
    Cmp -- no --> No(["❌ exit 1"]):::red
    P -. parse error .-> Err(["❌ error"]):::red
    classDef blue fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef green fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef red fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    classDef yellow fill:#fffbe6,stroke:#faad14,color:#874d00
```

## 用法

```bash
cvss canonicalize [vector-string] [flags]
```

### Flags

| Flag         | 类型   | 默认值  | 说明                                       |
| ------------ | ------ | ------- | ------------------------------------------ |
| `--check`    | bool   | `false` | 仅检查是否规范（退出码 0=是，1=否）        |
| `--format`   | string | `text`  | 输出格式：`text` 或 `json`                 |
| `-h, --help` | bool   | `false` | `canonicalize` 的帮助信息                  |

::: tip `--check` 可用于脚本
`--check` 在向量已规范时退出 `0`，否则退出 `1`，可直接用于 shell 的 `if` 判断与 CI 卡点。
:::

## 示例

::: code-group

```bash [已是规范形态]
cvss canonicalize "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

```text [输出]
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

:::

::: code-group

```bash [检查模式]
cvss canonicalize --check "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

```text [输出]
Canonical [PASS]
```

:::

::: warning 非规范示例
`canonicalize "CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N"`（指标乱序）会把向量重写为规范顺序；配合 `--check` 会打印 `Canonical [FAIL]` 并以 `1` 退出。
:::

## 底层 API

用 [`cvss.Canonicalize(str)`](/zh/sdk/sql-sort) 重排，用 [`cvss.IsCanonical(str)`](/zh/sdk/sql-sort) 实现 `--check`。

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

// 重排为规范顺序
canonical, err := cvss.Canonicalize("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatal(err)
}
fmt.Println(canonical)

// 仅检查
if cvss.IsCanonical("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
    fmt.Println("Canonical [PASS]")
}
```

## 相关

- [parse](/zh/cli/commands/parse) — 也会规范化向量字符串（经解析器处理）
- [validate](/zh/cli/commands/validate) — 在重排前后做校验
- [SQL 与排序](/zh/sdk/sql-sort) — Go SDK 参考
