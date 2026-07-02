---
layout: home

hero:
  name: CVSS Skills
  text: CVSS v3.0 / v3.1 工具包
  tagline: 解析、评分、验证、比较与构建漏洞向量 —— 通过 Go SDK、CLI、Claude Code Skills 与 MCP。
  image:
    src: /images/integration-methods.png
    alt: CVSS Skills 的四种集成方式
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/integration/
    - theme: alt
      text: 下载 CLI
      link: /zh/downloads/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🤖
    title: 4 种集成方式
    details: Claude Code Skills、Go SDK、CLI 与 MCP —— 从自然语言到批量脚本，按需选择。
    link: /zh/integration/
    linkText: 对比各方式 →
  - icon: 🧮
    title: 符合规范的评分
    details: 基础 / 时间 / 环境评分严格遵循 CVSS v3.0 与 v3.1 规范，包含版本差异（如 UI:R = 0.56 vs 0.62）。
  - icon: ✅
    title: 结构化校验
    details: 逐指标错误报告、完整性检查与缺失指标检测 —— 不再猜测向量哪里出错。
  - icon: 📊
    title: 比较与度量
    details: Diff、合并与距离度量（欧氏、曼哈顿、汉明、Jaccard、评分差），基于基础指标取值计算。
  - icon: 💻
    title: 30+ CLI 命令
    details: 可脚本化的 CLI，每条命令均支持 JSON 输出。预编译二进制覆盖 6 个操作系统（共 33 个归档包）。
    link: /zh/cli/
    linkText: 浏览命令 →
  - icon: 📦
    title: 一行安装
    details: Go SDK 用 go get，CLI 用 curl 或 go install，Skills 用一条 claude mcp add 命令。
---

## 解决什么问题？

CVSS 是业界标准的漏洞严重性评级体系，但以编程方式处理向量十分痛苦 —— 解析易错、评分涉及版本特定公式、比较依赖手工、校验零散。

**CVSS Skills** 用一个经过充分测试的工具包解决上述所有问题。

![功能全景图](/images/feature-map.png)

## 架构总览

四种集成方式 —— Skills、Go SDK、CLI、MCP —— 都是同一套经过充分测试的核心包之上的薄封装。模型学一次，处处可用。

```mermaid
flowchart TB
    subgraph Surfaces["集成层"]
        direction LR
        Skills["🤖 Claude Code Skills"]
        MCP["🔌 MCP 服务器"]
        CLI["💻 CLI (cvss)"]
        SDK["📦 Go SDK"]
    end

    subgraph Core["核心包"]
        direction LR
        Parser["pkg/parser<br/>向量字符串 → 结构体"]
        CVSS["pkg/cvss<br/>计算器 · 距离 · 差异"]
        Vector["pkg/vector<br/>Vector 接口"]
    end

    Skills --> CLI
    MCP --> CLI
    CLI --> Parser
    SDK --> Parser
    Parser --> Vector
    Vector --> CVSS
    CVSS --> Result(["评分 · 严重性 · JSON"])

    classDef surface fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    classDef core fill:#f6ffed,stroke:#52c41a,color:#135200;
    class Skills,MCP,CLI,SDK surface;
    class Parser,CVSS,Vector core;
```

## 从向量字符串到评分

标准流水线：原始向量字符串被解析为带类型的结构体，经校验后送入版本感知的计算器，产出评分与严重性等级。

```mermaid
flowchart LR
    A["CVSS:3.1/AV:N/...<br/>向量字符串"] --> B{解析}
    B -->|语法错误| E1["error<br/>（非法头部、<br/>畸形向量等）"]
    B -->|成功| C["Cvss3x 结构体"]
    C --> D{校验}
    D -->|指标缺失/非法| E2["ValidationErrors"]
    D -->|完整| F["计算器"]
    F --> O["整体评分<br/>（基础 → 时间 →<br/>环境，按存在者）"]
    O --> J["GetSeverity()"]
    J --> K(["9.8 · Critical"])

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class E1,E2 err;
```

## CVSS 向量结构

一个 CVSS 向量最多由 **3 层**指标构成：

![向量结构](/images/vector-structure.png)

```mermaid
flowchart TD
    Prefix["CVSS:3.1"] --> Base

    subgraph Base["基础指标 —— 必需（全部 8 个）"]
        direction LR
        AV["AV<br/>攻击途径"]
        AC["AC<br/>攻击复杂度"]
        PR["PR<br/>所需权限"]
        UI["UI<br/>用户交互"]
        S["S<br/>影响范围"]
        C["C<br/>机密性"]
        I["I<br/>完整性"]
        A["A<br/>可用性"]
    end

    subgraph Temporal["时间指标 —— 可选"]
        direction LR
        E["E<br/>利用成熟度"]
        RL["RL<br/>修复级别"]
        RC["RC<br/>报告可信度"]
    end

    subgraph Env["环境指标 —— 可选"]
        direction LR
        CR["CR / IR / AR<br/>安全性需求"]
        M["MAV…MA<br/>修正的基础指标"]
    end

    Base --> Temporal --> Env

    classDef base fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    classDef temporal fill:#fffbe6,stroke:#faad14,color:#874d00;
    classDef env fill:#f9f0ff,stroke:#722ed1,color:#391085;
    class AV,AC,PR,UI,S,C,I,A base;
    class E,RL,RC temporal;
    class CR,M env;
```

## 严重性等级

![严重性仪表盘](/images/severity-gauge.png)

| 等级     | 分数范围    | 颜色   |
| -------- | ----------- | ------ |
| None     | 0.0         | 灰色   |
| Low      | 0.1 – 3.9   | 绿色   |
| Medium   | 4.0 – 6.9   | 黄色   |
| High     | 7.0 – 8.9   | 橙色   |
| Critical | 9.0 – 10.0  | 红色   |

数值型基础评分通过 `GetSeverity()` 唯一映射到一个等级区间：

```mermaid
flowchart LR
    Score(["基础评分 0.0–10.0"]) --> D{落在哪个区间?}
    D -->|"= 0.0"| N["None"]
    D -->|"0.1 – 3.9"| L["Low"]
    D -->|"4.0 – 6.9"| M["Medium"]
    D -->|"7.0 – 8.9"| H["High"]
    D -->|"9.0 – 10.0"| Cr["Critical"]

    classDef none fill:#f0f0f0,stroke:#8c8c8c,color:#262626;
    classDef low fill:#f6ffed,stroke:#52c41a,color:#135200;
    classDef med fill:#fffbe6,stroke:#faad14,color:#874d00;
    classDef high fill:#fff7e6,stroke:#fa8c16,color:#873800;
    classDef crit fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class N none;
    class L low;
    class M med;
    class H high;
    class Cr crit;
```

::: tip v3.0 与 v3.1 —— 同一向量评分可能不同
上面的区间边界在两个版本间完全一致，但底层公式不同。CVSS v3.1 引入了明确定义的 **roundup（向上取整）** 函数，并重新调整了若干权重（例如 `UI:R` 在 v3.1 为 0.62、v3.0 为 0.56）。工具包会读取 `CVSS:3.0` / `CVSS:3.1` 前缀并自动套用对应公式 —— 因此请始终为向量保留版本前缀。
:::

## 快速开始

::: code-group

```bash [Claude Code Skills]
claude mcp add --scope user cvss-skills -- https://github.com/scagogogo/cvss-skills
```

```bash [Go SDK]
go get github.com/scagogogo/cvss-skills@latest
```

```bash [CLI (curl)]
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
case "$arch" in arm64) arch=aarch64 ;; amd64) arch=x86_64 ;; esac
ver=$(curl -sL https://api.github.com/repos/scagogogo/cvss-skills/releases/latest | sed -nE 's/.*"tag_name":\s*"v?([^"]+)".*/\1/p')
curl -sL "https://github.com/scagogogo/cvss-skills/releases/download/v${ver}/cvss-skills_${ver}_${os}_${arch}.tar.gz" | tar xz
sudo mv cvss /usr/local/bin/
```

```bash [CLI (go install)]
go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
```

:::

```bash
# 对向量评分 —— 每种集成方式效果相同
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# 输出: 9.8 (Critical)
```

## 下一步

- [集成方式](/zh/integration/) —— 对比 Skills、Go SDK、CLI 与 MCP，附决策树
- [CLI 参考](/zh/cli/) —— 全部 30+ 命令及示例
- [下载](/zh/downloads/) —— 各系统/架构的预编译二进制，含校验和验证
- [API 文档](/docs/zh/api/) —— 完整的 Go SDK 参考
