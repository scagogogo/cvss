---
title: 度量两个 CVSS 向量的相似度
description: 用 cvss distance 和 DistanceCalculator Go API 计算两个 CVSS 向量的欧氏、曼哈顿、汉明、Jaccard 距离与分数差。
---

# 📏 度量两个 CVSS 向量的相似度

## 问题

你要的是一个数字——不是一堆差异指标——来说两个 CVSS 向量差多远，用于去重、聚类或“找相似公告”。

## 方案

流程如下——一个计算器，五种度量，按用途选择：

```mermaid
flowchart LR
  V1[🔤 V1] & V2[🔤 V2] --> DC[⚙️ DistanceCalculator<br/>NewDistanceCalculator a, b]
  DC --> M{which metric?}
  M -- count diffs --> H[🔢 Hamming<br/>int 0–11]
  M -- normalized sim --> J[📊 Jaccard<br/>0–1, 1=identical]
  M -- outlier-weighted --> E[📐 Euclidean<br/>√Σ diff²]
  M -- robust to outlier --> MA[📐 Manhattan<br/>Σ|diff|]
  M -- final number only --> SD[🎯 Score diff<br/>|score a − score b|]
  H --> R[📋 rank / cluster / dedup]
  J --> R
  E --> R
  MA --> R
  SD --> R
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class V1,V2 in
  class DC step
  class M branch
  class H,J,E,MA,SD step
  class R out
```

### CLI：`distance`

```bash
cvss distance \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
```

```text
Euclidean:  0.9670
Manhattan:  2.4600
Hamming:    7
Jaccard:    0.1250
Score diff: 6.0
```

加 `--env` 把 11 个环境维度纳入计算：

```bash
cvss distance --env \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:H/AR:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/E:U/RL:O/RC:R/CR:L/IR:L/AR:L"
```

```text
Euclidean (with env):  1.9850
Manhattan (with env):  5.5700
Hamming (with env):    13
Jaccard (with env):    0.4091
Score diff: 7.4
```

要机器消费，用 `--format json`：

```bash
cvss distance --format json \
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
```

```json
{
  "euclidean": 0.9669539802906858,
  "hamming": 7,
  "jaccard": 0.125,
  "manhattan": 2.46,
  "score_diff": 6.000000000000001,
  "vector1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vector2": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
}
```

### Go SDK：`DistanceCalculator`

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
	a, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	b, _ := parser.ParseString("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")

	dc := cvss.NewDistanceCalculator(a, b)
	fmt.Printf("Euclidean : %.4f\n", dc.EuclideanDistance())
	fmt.Printf("Manhattan : %.4f\n", dc.ManhattanDistance())
	fmt.Printf("Hamming   : %d\n", dc.HammingDistance())
	fmt.Printf("Jaccard   : %.4f\n", dc.JaccardSimilarity())
	fmt.Printf("ScoreDiff : %.1f\n", dc.ScoreDifference())

	// 带环境指标的变体
	fmt.Printf("Euclidean (env): %.4f\n", dc.EuclideanDistanceWithEnv())

	// 带错误返回的变体——基础指标不完整时会显式报错
	if _, err := dc.EuclideanDistanceChecked(); err != nil {
		fmt.Println("checked error:", err)
	}
}
```

## 如何选度量

| 度量 | 衡量的是什么 | 范围 | 适用场景 |
| --- | --- | --- | --- |
| **Hamming** | 不同的指标个数 | 整数 0–11（基础） | 你要“差几个旋钮”，每个差异等权 |
| **Jaccard** | 相同 / 总指标 | 0–1（1 = 完全相同） | 你要一个 [0,1] 的归一化相似度 |
| **Euclidean** | √(Σ 分数差²) | ≥ 0 | 你在意分数空间差异的*幅度*，离群差异权重更大 |
| **Manhattan** | Σ \|分数差\| | ≥ 0 | 同 Euclidean，但对单个大离群更鲁棒 |
| **Score diff** | \|score(a) − score(b)\| | 0–10 | 你只关心最终那个数，单维度 |

::: tip Jaccard 是相似度，不是距离
`JaccardSimilarity` 对完全相同的向量返回 `1.0`，对完全不相交的返回 `0.0`。需要一个“相同为 0”的距离时，用 `1 - jaccard` 转换。
:::

## 讨论

- **plain 变体在不完整基础指标上静默返回 0。** 任一向量缺必需基础指标时，`EuclideanDistance()` 等返回 `0.0`——和“完全相同”看不出区别。用 `*Checked` 变体（`EuclideanDistanceChecked()`）拿到显式错误。
- **PR 和 UI 用的是上下文调整后的分数。** PR 的分数依赖 Scope，而 UI:R 在 v3.0 是 0.56、v3.1 是 0.62——距离计算已经考虑了这点，所以跨版本对比是有意义的。
- **Scope 是 0/1，不是分数。** Scope没有数值分数，距离代码把 scope 变化当成固定 `1.0` 的贡献。
- **`--env` 只在两边都有环境指标时才加维度。** 只有一边有时，env 变体会退回 base+temporal 的行为。
- **不是你想要的？** 要逐指标的人话版对比，看 [对比两个向量](/zh/recipes/compare-two-vectors)。

## 另见

- [`distance`](/zh/cli/commands/distance)——本篇用到的 CLI 命令
- [距离与对比](/zh/sdk/distance)——`DistanceCalculator` 参考（plain / `WithEnv` / `Checked`）
- [对比两个向量](/zh/recipes/compare-two-vectors)
- [影响与敏感度](/zh/sdk/impact)——单向量“哪个指标最要紧”
