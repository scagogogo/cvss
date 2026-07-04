---
title: 修改后指标 (M*) — 环境对基础指标的覆盖
description: CVSS 修改后指标 (MAV/MAC/MPR/MUI/MS/MC/MI/MA) 让环境覆盖基础指标。取值 X（Not Defined）时回退到基础值。
---

# 🔄 修改后指标 (M*)

🟩 环境指标 · 📐 基础指标覆盖（X 回退）

## 定义

八项修改后指标让环境**覆盖**每项基础指标，以反映漏洞在该具体部署中的行为。它们是**环境指标**。每个 `M*` 指标对应一项基础指标；设为 `X`（Not Defined）即告知评分器回退到对应基础值不变。

## 修改后指标

| 短名 | 长名 | 对应基础指标 | `X`（Not Defined）行为 |
| ---- | ---- | ------------ | ---------------------- |
| MAV  | 修改后攻击向量      | AV | 使用基础 AV 值 |
| MAC  | 修改后攻击复杂度    | AC | 使用基础 AC 值 |
| MPR  | 修改后所需权限      | PR | 使用基础 PR 值（Scope 感知） |
| MUI  | 修改后用户交互      | UI | 使用基础 UI 值（版本感知） |
| MS   | 修改后范围          | S  | 使用基础 S 值 |
| MC   | 修改后机密性        | C  | 使用基础 C 值 |
| MI   | 修改后完整性        | I  | 使用基础 I 值 |
| MA   | 修改后可用性        | A  | 使用基础 A 值 |

`X` 取值在 `pkg/vector/not_defined_vectors.go` 中静态分数为 **1.0**，向环境公式表示"不做修改"。

## 分数映射

```mermaid
flowchart TB
    Base["🧱 Base Metric (AV/AC/PR/UI/S/C/I/A)"]:::data
    M["🛠️ Modified Metric (MAV/MAC/...)"]:::data

    M -->|Value = X (Not Defined)| Fall["↩️ Fallback: use base value\n(score = 1.0 = no change)"]:::neutral
    M -->|Value != X (override)| Over["⬆️ Override base value"]:::crit

    Base --> Fall
    Base --> Over

    classDef data fill:#e6f4ff,stroke:#1677ff,color:#003a8c
    classDef neutral fill:#f6ffed,stroke:#52c41a,color:#135200
    classDef crit fill:#f9f0ff,stroke:#722ed1,color:#391085
```

修改后指标取 `X`（Not Defined，分数 **1.0**）时**回退**到基础指标值。其他取值则在环境公式中**覆盖**基础值。

## 评分影响

每项修改后指标设为具体取值时，在环境阶段重算基础分数时替换对应基础指标。设为 `X` 时改用基础值——因此该指标相当于消失，基础值透传。这让你可以只为本环境不同的维度做裁剪，其余保持基础值。

两个辅助函数处理棘手的回退：

- **MPR 为 `X`**：`GetPrivilegesRequiredScore(mpr, scopeChanged)` 对 `X`（或 nil）返回 `1.0`，环境公式随后经修改后 Scope 解析重新应用基础 PR。用 `IsModifiedScopeChanged(ms, baseScope)` 确定正确 Scope。
- **MUI 为 `X`**：`GetUserInteractionScore(mui, minorVersion)` 对 `X`（或 nil）返回 `1.0`，基础 UI 值透传。

## 示例

从基础 Critical 向量出发，仅将攻击向量覆盖为 `Local`：

```bash
# 仅基础（MAV:X 回退到 AV:N）
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:X"
# 在本环境将攻击向量覆盖为 Local
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L"
```

```text
Base: 9.8 (Critical), Environmental: 9.8 (Critical)   # MAV:X → 基础 AV:N
Base: 9.8 (Critical), Environmental: 8.4 (High)       # MAV:L 覆盖
```

`MAV:X` 时环境分数等于基础分数（AV:N 透传）。设 `MAV:L` 则将环境分数降至 8.4，反映本环境中攻击只能在本地发起。

Go SDK — 获取 `X`（Not Defined）变体：

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    // X 变体表示"回退到基础"。
    mavX, _ := vector.GetModifiedAttackVector('X')
    fmt.Println(mavX.IsNotDefined(), mavX.GetScore()) // true 1.0

    // 具体覆盖：
    mavL, _ := vector.GetModifiedAttackVector('L')
    fmt.Println(mavL.GetScore()) // 0.55
}
```

## 源码位置

修改后指标的预设变量与对应基础指标定义在同一 `.go` 文件中（如 `ModifiedAttackVectorLocal` 位于 `attack_vector.go`）。`X`（Not Defined）变体统一位于 [`pkg/vector/not_defined_vectors.go`](https://github.com/scagogogo/cvss-skills/blob/main/pkg/vector/not_defined_vectors.go)，分数均为 `1.0`。

## 相关

- [指标总览](./)
- [所需权限 (PR)](./privileges-required) — Scope 感知回退
- [用户交互 (UI)](./user-interaction) — 版本感知回退
- [安全需求 (CR/IR/AR)](./requirements)
