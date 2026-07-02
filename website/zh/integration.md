---
title: 集成方式
description: 对比使用 CVSS Skills 的四种方式 —— Claude Code Skills、Go SDK、CLI 与 MCP 服务器，并用决策树帮你为工作流选择合适的接入面。
---

# 集成方式

CVSS Skills 提供 **四种**集成方式，按你的工作流选择。

![集成方式](/images/integration-methods.png)

|          | 集成方式                   | 适用场景                          | 安装                                                                          |
| -------- | -------------------------- | --------------------------------- | ----------------------------------------------------------------------------- |
| 🤖       | **Skills**（Claude Code）  | 交互式分析、自然语言              | `claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills` |
| 📦       | **Go SDK**                 | Go 语言安全工具开发与自动化       | `go get github.com/scagogogo/cvss-skills@latest`                              |
| 💻       | **CLI**                    | 脚本化、批量处理、快速查询        | 见[下载](/zh/downloads/)                                                      |
| 🔌       | **MCP**                    | 通过模型上下文协议集成 AI 智能体   | 从任意兼容 MCP 的客户端将本仓库添加为 MCP 服务器                               |

::: details 每种方式何时适用、何时不适用
| 接入面      | 适合在以下情况使用…                              | 换用其他方式，当…                                       |
| ----------- | ----------------------------------------------- | ------------------------------------------------------ |
| **Skills**  | 你已在 Claude Code 中，想用自然语言分析          | 需要脚本里可复现的输出 → 改用 **CLI**                   |
| **Go SDK**  | 你在构建 Go 服务，想要编译期类型安全             | 不写 Go → 改用 **CLI** 或 **MCP**                       |
| **CLI**     | 你想在 Shell 或 CI 中用可管道、输出 JSON 的命令  | 需要进程内访问中间结构体 → 改用 **Go SDK**              |
| **MCP**     | 你的智能体（Claude Desktop、Continue、自定义）讲 MCP | 你正好在 Claude Code 里 → **Skills** 更直接           |

四种方式共用同一套评分核心，因此各接入面的结果完全一致 —— 选择纯粹取决于使用习惯。
:::

## 我该用哪种方式？

```mermaid
flowchart TD
    Start(["我需要处理 CVSS 向量"]) --> Q1{是否在与<br/>AI 智能体对话?}
    Q1 -->|是，用 Claude Code| Skills["🤖 Skills<br/>自然语言命令"]
    Q1 -->|是，用其他客户端| MCP["🔌 MCP<br/>标准协议"]
    Q1 -->|否| Q2{在写 Go 代码?}
    Q2 -->|是| SDK["📦 Go SDK<br/>完整类型安全 API"]
    Q2 -->|否| Q3{Shell 脚本<br/>或一次性查询?}
    Q3 -->|是| CLI["💻 CLI<br/>对 JSON 友好的命令"]
    Q3 -->|只是探索| CLI

    classDef pick fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    class Skills,MCP,SDK,CLI pick;
```

## 各集成层如何协作

CLI、Skills、MCP 三个层最终都调用同一套 Go 核心，评分逻辑没有任何重复实现：

```mermaid
sequenceDiagram
    autonumber
    actor User as 用户
    participant Agent as AI 智能体 / Shell
    participant CLI as cvss CLI
    participant Core as pkg/cvss + pkg/parser
    User->>Agent: “给 CVSS:3.1/AV:N/... 评分”
    Agent->>CLI: cvss score "<向量>" --format json
    CLI->>Core: parser.ParseString → NewCalculator → Calculate
    Core->>Core: 解析 → 校验 → 计算
    Core-->>CLI: score, severity, err
    CLI-->>Agent: {"score":9.8,"severity":"Critical"}
    Agent-->>User: 9.8 (Critical)
```

## 1. Claude Code Skills

把本仓库加为 skill 源后，Claude Code 即可按名称调用 **9 个 CVSS 技能**：

| 技能               | 描述                                |
| ------------------- | ----------------------------------- |
| `cvss-parse`        | 解析 CVSS v3.0/v3.1 向量字符串      |
| `cvss-score`        | 计算基础/时间/环境评分              |
| `cvss-validate`     | 校验向量完整性与正确性              |
| `cvss-construct`    | 用 Builder API 构建向量             |
| `cvss-compare`      | Diff、合并与距离计算                |
| `cvss-metrics`      | 枚举与查看指标定义                  |
| `cvss-serialize`    | JSON/文本序列化与反序列化           |
| `cvss-advanced`     | 敏感性分析、分数范围、预设          |
| `cvss-install`      | 安装 CLI 工具与 Go SDK 依赖         |

每个技能是 `.claude/skills/` 下的一个 markdown 指导文件，告诉 Claude 应运行哪条 `cvss` CLI 命令、如何解读输出 —— 因此你只需用自然语言提问（如「给这个向量评分：…」），Claude 会自动选用正确的技能。

::: details 手动安装
添加到项目的 `.claude/settings.json` 或 `~/.claude/settings.json`：

```json
{
  "mcpServers": {
    "cvss-skills": {
      "type": "github",
      "url": "https://github.com/scagogogo/cvss-skills"
    }
  }
}
```

:::

## 2. Go SDK

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // 一步解析并评分
    cv, score, severity, err := parser.ParseAndScore(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Score: %.1f (%s)\n", score, severity) // Score: 9.8 (Critical)
    _ = cv
}
```

完整 API 参考：[API 文档](/docs/zh/api/)。

::: tip 常见路径优先用 `ParseAndScore`
`parser.ParseAndScore` 把解析 → 校验 → 计算合并为一次调用。只有当你需要中间的 `Cvss3x` 结构体时（例如查看单个指标或对比两个向量），才降级到 `parser.ParseString` + `cvss.NewCalculator`。
:::

## 3. CLI

```bash
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# 输出: 9.8 (Critical)
```

全部 30+ 命令见 [CLI 参考](/zh/cli/)。

## 4. MCP

从任意兼容 MCP 的客户端（Claude Desktop、Continue、自定义智能体）将本仓库连接为 MCP 服务器，即可通过标准模型上下文协议使用 CVSS 工具。
