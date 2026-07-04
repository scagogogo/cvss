---
title: 生成随机 CVSS 向量作为测试数据
description: 用 cvss random 命令和 mock.RandomCvss3xFull Go API 生成随机 CVSS 3.x 向量，用于测试夹具和属性测试。
---

# 🎲 生成随机 CVSS 向量作为测试数据

## 问题

你需要 CVSS 向量来填充测试数据库、写属性测试或给仪表盘做演示——但手写合法向量又枯燥、又偏向几个熟悉的套路。

## 方案

流程如下：

```mermaid
flowchart LR
  R[🎲 random source] --> G{which generator?}
  G -- cvss random --> C1[🔤 base-only vector<br/>default v3.1]
  G -- --temporal --> C2[🔤 + E RL RC]
  G -- --full --> C3[🔤 + temporal + env<br/>all 11 metrics]
  G -- mock.RandomCvss3x* --> C4[⚙️ *Cvss3x object<br/>no re-parse]
  C1 --> V[✅ valid, scoreable vector]
  C2 --> V
  C3 --> V
  C4 --> V
  V --> U[🧪 test DB / fixtures<br/>property tests]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef branch fill:#fffbe6,stroke:#faad14,color:#874d00
  class R in
  class C1,C2,C3,C4 step
  class G branch
  class V,U out
```

### CLI：`random`

`cvss random` 输出一个合法的、仅含基础指标的 v3.1 向量，各指标值均匀随机：

```bash
cvss random
```

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:H
```

每次调用都不同。常用 flag：

```bash
cvss random --score         # 附带算好的分数
cvss random --temporal      # 加 E/RL/RC
cvss random --full          # 加时间 + 环境指标
cvss random --cvss-version 3.0   # 用 v3.0 而非 v3.1
cvss random --format json   # {"vector": "..."}
```

```bash
cvss random --score
```

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
Score: 7.1 (High)
```

```bash
cvss random --temporal
```

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L/E:H/RL:T/RC:R
```

```bash
cvss random --format json
```

```json
{
  "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:H"
}
```

循环生成一批：

```bash
for i in $(seq 1 5); do cvss random; done > fixtures.txt
```

### Go SDK：`mock.RandomCvss3xFull`

`pkg/mock` 包直接给你对象，省去把字符串再 parse 回来。`RandomCvss3x` 只有基础指标，`RandomCvss3xWithTemporal` 加 E/RL/RC，`RandomCvss3xFull` 加全部 11 个环境指标。参数是次版本号（`0` 或 `1`）。

```go
package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/mock"
)

func main() {
	// 仅基础指标的 v3.1。
	fmt.Println(mock.RandomCvss3x(1).String())

	// 全量（时间 + 环境）v3.1。
	full := mock.RandomCvss3xFull(1)
	fmt.Println(full.String())

	// 带分数。
	cv, score, err := mock.RandomCvss3xWithScore(1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s -> %.1f\n", cv.String(), score)

	// v3.0 随机向量串。
	fmt.Println(mock.RandomCvss3xVectorString(0))
}
```

某次运行的输出：

```text
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L/E:X/RL:W/RC:R/CR:L/IR:L/AR:M/MAV:X/MAC:H/MPR:H/MUI:N/MS:C/MC:X/MI:H/MA:L
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N -> 5.3
CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:N
```

::: tip 可复现的随机性
`pkg/mock` 用 `math/rand` 且未播种。要确定性的测试夹具，在测试开头播种全局源（`rand.Seed(42)`），或者一次性把生成的字符串固化到 golden 文件里再提交。
:::

## 讨论

- **每个生成的向量都合法、可评分。** `RandomCvss3xFull` 把每个指标都设成合法值，所以 `NewCalculator(cv).Calculate()` 不会报错。
- **分布是按指标均匀，不是按分数均匀。** 每个指标独立选取，所以分数分布*不是*均匀的——极端分（0.0、10.0）比中段分更少见。如果你要*特定*严重性的向量，用 [`build`](/zh/cli/commands/build) 构造，或用 [preset](/zh/cli/commands/preset)。
- **`--full` 可能含 `X`（Not Defined）。** 环境指标会包含 `X` 值，calculator 把它当“继承基础指标”——所以全量随机向量仍能合理评分。
- **不是你想要的？** 要固定严重性的向量，用 [`preset`](/zh/cli/commands/preset) 命令，或 Go 里的 `cvss.CriticalV31()` / `HighV31()` / `MediumV31()` / `LowV31()` / `NoneV31()`。

## 另见

- [`random`](/zh/cli/commands/random)——本篇用到的 CLI 命令
- [`preset`](/zh/cli/commands/preset)——固定严重性的向量
- [Mock 与随机](/zh/sdk/mock)——`RandomCvss3x` / `RandomCvss3xFull` / `RandomCvss3xWithScore` 参考
- [预设向量](/zh/sdk/presets)——`CriticalV31` 等
- [存入数据库](/zh/recipes/store-in-database)
