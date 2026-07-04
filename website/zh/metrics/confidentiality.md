---
title: 机密性 (C) — 对信息保密性的影响
description: CVSS 机密性指标 (C) 衡量受影响组件内机密性的损失程度——High、Low 或 None。
---

# 🔒 机密性 (C)

🟦 基础指标 · 📐 影响子分

## 定义

机密性 (C) 衡量受影响组件内机密性的损失程度——信息向未授权方披露的程度。它与完整性、可用性同为构成**影响 (Impact)** 子分的三项 CIA 指标之一。

## 取值

| 短值 | 长值 | 分数 | 描述 |
| ---- | ---- | ---- | ---- |
| `H` | High | 0.56 | 机密性完全丧失，或披露的限制信息具有直接且严重的影响（如管理员密码、私钥被盗）。 |
| `L` | Low  | 0.22 | 机密性有所损失；获得部分受限信息，但披露有限且非直接严重。 |
| `N` | None | 0.00 | 受影响组件内无机密性损失。 |

分数取自 `pkg/vector/confidentiality.go`。

## 分数映射

```mermaid
flowchart LR
    H["🔓 High (H)"]:::high
    L["🔐 Low (L)"]:::mid
    N["✅ None (N)"]:::low

    H -->|"0.56"| SH["🧮 0.56"]:::data
    L -->|"0.22"| SL["🧮 0.22"]:::data
    N -->|"0.00"| SN["🧮 0.00"]:::data

    classDef high fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef mid fill:#fffbe6,stroke:#faad14,color:#874d00
    classDef low fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
    classDef data fill:#e6f4ff,stroke:#1677ff,color:#003a8c
```

C、I、A 三个指标**分数刻度相同**（H=0.56、L=0.22、N=0.00）。它们汇入 ISC（影响）子分：取值越高影响越大。完全损失（H）影响最大；无损失（N）不计。

## 评分影响

C 喂入**影响**子分（与 I、A 一同）。三者按 `Impact = 1 − (1 − C) × (1 − I) × (1 − A)` 合并。仅 C 有影响时，`C:H` 得影响 0.56，`C:L` 得 0.22，`C:N` 得 0（无影响、零分）。

## 示例

将 I、A 设为 `None` 以单独观察 C：

```bash
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # C:High
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # C:Low
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # C:None
```

```text
7.5 (High)     # C:H
5.3 (Medium)   # C:L
0.0 (None)     # C:N
```

Go SDK：

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    h, _ := vector.GetConfidentiality('H')
    l, _ := vector.GetConfidentiality('L')
    n, _ := vector.GetConfidentiality('N')
    fmt.Printf("C:H=%.2f  C:L=%.2f  C:N=%.2f\n", h.GetScore(), l.GetScore(), n.GetScore())
}
```

## 源码位置

[`pkg/vector/confidentiality.go`](https://github.com/scagogogo/cvss-skills/blob/main/pkg/vector/confidentiality.go) — 定义 `ConfidentialityHigh` (0.56)、`ConfidentialityLow` (0.22)、`ConfidentialityNone` (0)，以及 `MC` 修改后变体。

## 相关

- [指标总览](./)
- [完整性 (I)](./integrity)
- [可用性 (A)](./availability)
- [安全需求 (CR/IR/AR)](./requirements)
- [修改后指标 (M*)](./modified)
