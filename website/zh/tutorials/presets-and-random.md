---
title: 预设与随机
description: 用 preset 命令为每个严重性等级生成规范 CVSS 向量，用 random 和 Go 的 mock.RandomCvss3x 生成随机测试向量。
---

# 🎲 预设与随机

⏱️ 12 分钟 · 中级 · CLI + SDK

两个生成任务反复出现：为某个严重性生成"代表性"向量（用于文档、默认值或冒烟测试），以及生成*随机*向量（用于基于性质的测试和演示）。CLI 给你 `preset` 和 `random`；Go SDK 给你 `pkg/mock`。本教程练习两者。

## 前置条件

- `$PATH` 上的 `cvss` 二进制（或仓库根的 `./cvss-cli`）
- 学完 [getting-started](./getting-started)
- SDK 小节：Go 1.18+

## 流程

```mermaid
flowchart LR
  G{what to generate?} --> P[fixed severity?]
  G --> R[random?]
  P --> PR{cvss preset}
  PR -- critical --> P1[🔟 S:C → 10.0]
  PR -- high --> P2[9️⃣ S:U → 9.8 Critical]
  PR -- medium --> P3[6️⃣ C:L/I:L/A:N → 6.5]
  PR -- low --> P4[3️⃣ AC:H + I:N/A:N → 3.7]
  PR -- none --> P5[0️⃣ C:N/I:N/A:N → 0.0]
  R --> RR{cvss random}
  RR -- base --> RB[🔤 base only]
  RR -- --temporal --> RT[🔤 + E RL RC]
  RR -- --full --> RF[🔤 + env all 11]
  RR -- mock pkg --> RM[⚙️ *Cvss3x direct]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class G branch
  class P,R step
  class PR,RR branch
  class P1,P2,P3,P4,P5,RB,RT,RF,RM step
```

## 第 1 步 —— 每个严重性的预设向量

`preset <severity>` 打印落在请求严重性区间的规范向量。支持五个等级：`critical`、`high`、`medium`、`low`、`none`。加 `--score` 同时看分数。

```bash
cvss preset critical --score
cvss preset high --score
cvss preset medium --score
cvss preset low --score
cvss preset none --score
```

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 10.0 (Critical)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
Score: 6.5 (Medium)
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Score: 3.7 (Low)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
Score: 0.0 (None)
```

读这条递进——每个预设都离邻居差一个指标的杠杆：

| 预设 | 向量 | 分数 | 造就它的杠杆 |
| --- | --- | --- | --- |
| `critical` | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | `S:C`（改变范围）抬高封顶 |
| `high` | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | `S:U` 把 ISC 封在 6.42 |
| `medium` | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | 6.5 | 影响降到 `C:L/I:L/A:N` |
| `low` | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 3.7 | `AC:H` 加 `I:N/A:N` |
| `none` | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0.0 | 零影响（`C:N/I:N/A:N`） |

::: warning 名为 "high" 的预设评分是 9.8 Critical
名为 `high` 的预设产出的向量评分是 **9.8（Critical）**，不是 High。名字指的是它在递进中的*槽位*，不是结果严重性档。9.8→10.0 这一步是 `S:U`→`S:C` 杠杆，而用这些精确预设无法落在 7.0–8.9 的 High 档——High 严重性通常来自对 9.8 向量的时间/环境降分，见 [scoring-walkthrough](./scoring-walkthrough)。
:::

## 第 2 步 —— v3.0 预设

`--version 3.0` 用 v3.0 权重发同样形状的预设：

```bash
cvss preset --version 3.0 --score high
```

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
```

对 `UI:N` 预设，v3.0 与 v3.1 分数完全一致；只有 `UI:R` 会不同（见 [version-migration](./version-migration)）。

## 第 3 步 —— 预设的 JSON 形式

```bash
cvss preset --format json critical
```

```json
{
  "severity": "critical",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
}
```

JSON 形式不带分数——需要时用 `--score` 的文本形式，或把向量管到 `cvss score` 取数。

## 第 4 步 —— 随机向量

`random` 输出指标值随机的向量。默认仅基础；flag 加时间和环境。

```bash
cvss random
```

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:L
```

::: warning 随机输出不确定
每次 `cvss random` 调用产出不同向量。本教程展示的输出是样本——你的运行结果会不同。不要在测试里硬编码；如需确定性，请用种子或预设。
:::

加 `--score` 给随机向量评分：

```bash
cvss random --score
```

```
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L
Score: 5.1 (Medium)
```

加 `--temporal` 加时间指标：

```bash
cvss random --temporal --score
```

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:U/RL:T/RC:X
Score: 4.0 (Medium)
```

加 `--full` 加完整环境层（时间 + 环境 + 修改后指标）：

```bash
cvss random --full --score
```

```
CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L/E:P/RL:T/RC:X/CR:L/IR:H/AR:L/MAV:L/MAC:L/MPR:X/MUI:R/MS:U/MC:L/MI:H/MA:L
Score: 5.6 (Medium)
```

用 `--cvss-version 3.0` 生成 v3.0 随机向量：

```bash
cvss random --cvss-version 3.0 --full --score
```

JSON 形式：

```bash
cvss random --format json
```

```json
{
  "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H"
}
```

## 第 5 步 —— Go 中的随机向量：`pkg/mock`

单元测试时，`pkg/mock` 包直接生成随机 `*Cvss3x`——无需解析字符串。四个入口覆盖与 CLI flag 相同的层级：

| 函数 | CLI 等价 | 输出 |
| --- | --- | --- |
| `mock.RandomCvss3x(minor)` | `cvss random` | 仅基础 |
| `mock.RandomCvss3xWithTemporal(minor)` | `cvss random --temporal` | 基础 + 时间 |
| `mock.RandomCvss3xFull(minor)` | `cvss random --full` | 基础 + 时间 + 环境 |
| `mock.RandomCvss3xVectorString(minor)` | （字符串形式） | 纯向量串 |
| `mock.RandomCvss3xWithScore(minor)` | `cvss random --score` | `(*Cvss3x, score, error)` |

`minor` 是 CVSS 次版本号：`1` 表示 v3.1，`0` 表示 v3.0。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/mock"
)

func main() {
	// 仅基础的随机 v3.1 向量
	cv := mock.RandomCvss3x(1)
	fmt.Println("base:    ", cv.String())

	// 带时间
	cvt := mock.RandomCvss3xWithTemporal(1)
	fmt.Println("temporal:", cvt.String())

	// 完整（时间 + 环境）
	cvf := mock.RandomCvss3xFull(1)
	fmt.Println("full:    ", cvf.String())

	// 仅向量串
	fmt.Println("string:  ", mock.RandomCvss3xVectorString(1))

	// 带分数
	cv2, score, err := mock.RandomCvss3xWithScore(1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("scored:  %s -> %.1f\n", cv2.String(), score)

	// 把随机向量喂给计算器（典型测试模式）
	calc := cvss.NewCalculator(mock.RandomCvss3x(1))
	s, _ := calc.Calculate()
	fmt.Printf("calc:    %.1f\n", s)
}
```

```
base:     CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N
temporal: CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H/E:F/RL:X/RC:U
full:     CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L/E:X/RL:T/RC:C/CR:M/IR:H/AR:M/MAV:A/MAC:X/MPR:N/MUI:X/MS:U/MC:H/MI:L/MA:N
string:   CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:L
scored:   CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:H -> 6.0
calc:     0.0
```

::: tip mock 向量是随机的——不要断言确切分数
`mock.RandomCvss3x*` 用于填充计算器管道、生成夹具、或用*合法*向量走某条代码路径。如果测试需要稳定分数，改用预设或手建向量。
:::

## 第 6 步 —— 基于性质的测试模式

`mock` 的常见用法是一个循环，在许多随机向量上断言不变式——例如"每个合法基础向量评分在 0 到 10 之间"：

```go
func TestRandomVectorScoreInRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		cv := mock.RandomCvss3x(1)
		score, err := cvss.NewCalculator(cv).Calculate()
		if err != nil {
			t.Fatalf("random vector failed to score: %v", err)
		}
		if score < 0 || score > 10 {
			t.Fatalf("score %.1f out of range for %s", score, cv.String())
		}
	}
}
```

这能捕获评分公式的回归，无需你手工枚举每个向量。

## 小结

- `cvss preset <critical|high|medium|low|none>` 为每个严重性发规范向量；`--score` 看分数，`--version 3.0` 切规范。
- `high` 预设评分 9.8（Critical）——名字是槽位，不是档位。
- `cvss random` 发随机向量；`--temporal` / `--full` 加层级，`--score` 评分，`--cvss-version 3.0` 切规范。输出不确定。
- Go 中 `pkg/mock` 提供 `RandomCvss3x`、`RandomCvss3xWithTemporal`、`RandomCvss3xFull`、`RandomCvss3xVectorString`、`RandomCvss3xWithScore` 供测试。

## 下一步

- 在 [building-vectors](./building-vectors) 中把预设当起点再修改
- 在 [version-migration](./version-migration) 中看 `UI:R` 如何跨版本移动分数
