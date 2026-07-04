---
title: 概念与原理
description: CVSS v3.0/v3.1 的概念与原理文档 —— 严重性等级、评分公式、版本差异、校验模型、距离度量与预设向量。
---

# 📚 概念与原理

## 简介

**概念**章节解释 CVSS Skills 工具包背后的 *为什么* —— 评分数学、严重性阈值、v3.0↔v3.1 差异，以及每条命令和 SDK 调用所依赖的校验/比较模型。

如果 [CLI 参考](/zh/cli/) 与 [Go SDK](/zh/sdk/) 文档告诉你 *调用什么*，本章节则告诉你 *这些数字的含义与来源*。下文每个公式、阈值与常量均取自 Go 源码，无一杜撰。

## 学习路径

从上到下通读可获得完整心智模型，也可直接跳转到所需主题：

```mermaid
flowchart LR
    A["1. 严重性<br/>等级"] --> B["2. 评分<br/>公式"]
    B --> C["3. v3.0 与<br/>v3.1 差异"]
    C --> D["4. 校验<br/>模型"]
    D --> E["5. 距离<br/>度量"]
    E --> F["6. 预设向量"]
    style A fill:#0a7d28,color:#fff
    style F fill:#b3261e,color:#fff
```

| 步骤 | 主题 | 你将学到 |
|------|------|---------|
| 1 | [严重性等级](./severity) | None/Low/Medium/High/Critical 五档、阈值表，以及分数到等级的映射。 |
| 2 | [评分公式](./scoring-formula) | Base = `roundup(min(ISC+ESC, 10))`，以及 Temporal、Environmental 扩展。 |
| 3 | [v3.0 与 v3.1 差异](./version-diff) | 两处版本特定差异：`UI:R` 分数与 `roundUp` 算法。 |
| 4 | [校验模型](./validation) | `Check`（短路）与 `Validate`（收集全部），以及哨兵错误。 |
| 5 | [距离度量](./distance) | 欧氏、曼哈顿、汉明、Jaccard、评分差五种，及其 `env`/`checked` 变体。 |
| 6 | [预设与严重性](./presets) | 现成的 `CriticalV31`/`HighV31`/... 向量与 `WithCriticalBase` 选项。 |

## 代码位置

所有概念都映射到具体源码文件：

- `pkg/cvss/severity.go` —— `Severity` 类型、`GetSeverity`、`ParseSeverity`
- `pkg/cvss/calculator.go` —— `calculateBaseScore`、`roundUp`、`calculateTemporalScore`、`calculateEnvironmentalScore`
- `pkg/cvss/scores.go` —— `GetBaseScore`、`GetAllScores`、`RoundUp`
- `pkg/cvss/validate.go` / `pkg/cvss/errors.go` —— `Validate`、`ValidationErrors`、哨兵错误
- `pkg/cvss/distance.go` / `distance_env.go` / `distance_checked.go` —— 五种度量及变体
- `pkg/cvss/presets.go` / `options.go` / `pkg/mock/presets.go` —— 预设向量与选项
- `pkg/vector/user_interaction.go` —— `UI:R` 的 0.56/0.62 版本分支

## 相关

- [Go SDK 总览](/zh/sdk/) —— 实现这些概念的包级 API
- [CLI 参考](/zh/cli/) —— 同一核心之上的命令行封装
- [CVSS 指标](/zh/metrics/) —— 各指标的取值参考
