---
title: 按严重性排序 CVSS 向量
description: 用 cvss sort 命令按分数对一批 CVSS 向量排序，以及等价的 Go 代码 Cvss3xSlice。
---

# 🔢 按严重性排序 CVSS 向量

## 问题

你有一批 CVSS 向量，想按分数排序——分诊时要最严重的在前，清理报告时要最轻的在前。

## 方案

流程如下：

```mermaid
flowchart LR
  V[📄 vectors.txt<br/>one vector per line] --> S[🔢 score every vector<br/>cache scores]
  S --> O{order?}
  O -- default desc 🔽 --> D[✅ highest score first<br/>Critical → None]
  O -- --asc 🔼 --> A[✅ lowest score first<br/>None → Critical]
  O -- invalid → score −1 --> X[⚠️ sorts to top<br/>guard with ScoreAt < 0]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef warn fill:#fff1f0,stroke:#ff4d4f,color:#a8071a
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class V in
  class S step
  class O branch
  class D,A out
  class X warn
```

### CLI：`sort`

给定 `vectors.txt`（每行一个向量），`sort` 默认**降序**（分数高的在前）：

```bash
cvss sort vectors.txt
```

```text
10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
5.3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
3.8  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L
0.0  CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N
```

要升序（最轻的在前），加 `--asc`：

```bash
cvss sort --asc vectors.txt
```

```text
0.0  CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N
3.8  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L
5.3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
9.8  CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

`sort` 也能从 stdin 读，用 `-`：

```bash
cat vectors.txt | cvss sort -
```

### Go SDK：`Cvss3xSlice`

`cvss.NewCvss3xSlice` 预先算好每个向量的分数并实现 `sort.Interface`。默认降序；升序在 `.Sort()` 前调 `.Asc()`。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	v1 := cvss.CriticalV31() // 10.0, S:C
	v2 := cvss.HighV31()     // 9.8,  S:U
	v3 := cvss.LowV31()      // 3.7

	// 降序——Critical 在前（默认）。
	desc := cvss.NewCvss3xSlice(v1, v2, v3).Sort()
	for i, cv := range desc.Items() {
		fmt.Printf("#%d %.1f %s\n", i+1, desc.ScoreAt(i), cv.String())
	}

	// 升序——最轻的在前。
	_ = cvss.NewCvss3xSlice(v1, v2, v3).Asc().Sort()
}
```

降序循环的输出：

```text
#1 10.0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
#2 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
#3 3.7 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
```

`ScoreAt(i)` 返回缓存的分数，所以排序后读分数是零开销的——不用重算。

## 讨论

- **默认不是稳定排序。** 两个 9.8 的向量只有在用 `sort.Stable(slice)` 而非 `slice.Sort()`（后者用的是 `sort.Sort`）时才保持输入顺序。CLI `sort` 不稳定，所以同分向量可能任意排列。
- **无效向量被排到 −1。** `NewCvss3xSlice` 对 `Calculate` 失败的项记 `-1`，降序时它们会排在*最前*（−1 比谁都“大”）——如果输入可能含不完整向量，用 `if slice.ScoreAt(i) < 0 { continue }` 跳过。
- **构造时缓存分数。** 构造切片后改了向量，缓存的分数就过期了；向量变了就重建切片。
- **不是你想要的？** 要筛选而不是排序，看 [筛选 Critical 漏洞](/zh/recipes/filter-critical-vulns)。要把排序结果存数据库，看 [存入数据库](/zh/recipes/store-in-database)。

## 另见

- [`sort`](/zh/cli/commands/sort)——本篇用到的 CLI 命令
- [SQL 与排序](/zh/sdk/sql-sort)——`Cvss3xSlice` API 参考
- [筛选 Critical 漏洞](/zh/recipes/filter-critical-vulns)
- [存入数据库](/zh/recipes/store-in-database)
