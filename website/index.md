---
layout: home

hero:
  name: CVSS Skills
  text: CVSS v3.0 / v3.1 Toolkit
  tagline: Parse, score, validate, compare & build vulnerability vectors — through Go SDK, CLI, Claude Code Skills & MCP.
  image:
    src: /images/integration-methods.png
    alt: Four integration methods of CVSS Skills
  actions:
    - theme: brand
      text: Get Started
      link: /integration/
    - theme: alt
      text: Download CLI
      link: /downloads/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cvss-skills

features:
  - icon: 🤖
    title: 4 Integration Methods
    details: Claude Code Skills, Go SDK, CLI, and MCP — pick the one that fits your workflow, from natural language to batch scripting.
    link: /integration/
    linkText: Compare methods →
  - icon: 🧮
    title: Spec-Accurate Scoring
    details: Base / Temporal / Environmental scores following CVSS v3.0 & v3.1 specs, including version-specific quirks (e.g. UI:R = 0.56 vs 0.62).
  - icon: ✅
    title: Structured Validation
    details: Per-metric error reporting, completeness checks, and missing-metric detection — no more guessing what's wrong with a vector.
  - icon: 📊
    title: Compare & Measure
    details: Diff, merge, and distance metrics (Euclidean, Manhattan, Hamming, Jaccard, score-delta) over base metric values.
  - icon: 💻
    title: 30+ CLI Commands
    details: Scriptable CLI with JSON output for every command. Pre-built binaries for 6 operating systems (33 archive packages).
    link: /cli/
    linkText: Browse commands →
  - icon: 📦
    title: One-Line Install
    details: Go SDK via go get, CLI via curl or go install, Skills via a single claude mcp add command.
---

## What Problem Does This Solve?

CVSS is the industry standard for rating vulnerability severity, but working with vectors programmatically is painful — parsing is error-prone, scoring involves version-specific formulas, comparison is manual, and validation is scattered.

**CVSS Skills** solves all of this with a single, well-tested toolkit.

![Feature Map](/images/feature-map.png)

## Architecture at a Glance

Every integration method — Skills, Go SDK, CLI, and MCP — is a thin surface over the same well-tested core packages. Learn the model once; use it everywhere.

```mermaid
flowchart TB
    subgraph Surfaces["Integration Surfaces"]
        direction LR
        Skills["🤖 Claude Code Skills"]
        MCP["🔌 MCP Server"]
        CLI["💻 CLI (cvss)"]
        SDK["📦 Go SDK"]
    end

    subgraph Core["Core Packages"]
        direction LR
        Parser["pkg/parser<br/>vector → struct"]
        CVSS["pkg/cvss<br/>Calculator · Distance · Diff"]
        Vector["pkg/vector<br/>Vector interface"]
    end

    Skills --> CLI
    MCP --> CLI
    CLI --> Parser
    SDK --> Parser
    Parser --> Vector
    Vector --> CVSS
    CVSS --> Result(["Score · Severity · JSON"])

    classDef surface fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    classDef core fill:#f6ffed,stroke:#52c41a,color:#135200;
    class Skills,MCP,CLI,SDK surface;
    class Parser,CVSS,Vector core;
```

## From Vector String to Score

The canonical pipeline: a raw vector string is parsed into a typed struct, validated, then run through the version-aware calculator to produce a score and severity rating.

```mermaid
flowchart LR
    A["CVSS:3.1/AV:N/...<br/>vector string"] --> B{Parse}
    B -->|syntax error| E1["error<br/>(invalid magic head,<br/>malformed vector, …)"]
    B -->|ok| C["Cvss3x struct"]
    C --> D{Validate}
    D -->|missing/invalid metric| E2["ValidationErrors"]
    D -->|complete| F["Calculator"]
    F --> O["Overall score<br/>(base → temporal →<br/>environmental, as present)"]
    O --> J["GetSeverity()"]
    J --> K(["9.8 · Critical"])

    classDef err fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    class E1,E2 err;
```

## CVSS Vector Structure

A CVSS vector consists of up to **3 layers** of metrics:

![Vector Structure](/images/vector-structure.png)

```mermaid
flowchart TD
    Prefix["CVSS:3.1"] --> Base

    subgraph Base["Base Metrics — required (all 8)"]
        direction LR
        AV["AV<br/>Attack Vector"]
        AC["AC<br/>Attack Complexity"]
        PR["PR<br/>Privileges Req."]
        UI["UI<br/>User Interaction"]
        S["S<br/>Scope"]
        C["C<br/>Confidentiality"]
        I["I<br/>Integrity"]
        A["A<br/>Availability"]
    end

    subgraph Temporal["Temporal Metrics — optional"]
        direction LR
        E["E<br/>Exploit Maturity"]
        RL["RL<br/>Remediation Level"]
        RC["RC<br/>Report Confidence"]
    end

    subgraph Env["Environmental Metrics — optional"]
        direction LR
        CR["CR / IR / AR<br/>Requirements"]
        M["MAV…MA<br/>Modified Base"]
    end

    Base --> Temporal --> Env

    classDef base fill:#e6f4ff,stroke:#1677ff,color:#003a8c;
    classDef temporal fill:#fffbe6,stroke:#faad14,color:#874d00;
    classDef env fill:#f9f0ff,stroke:#722ed1,color:#391085;
    class AV,AC,PR,UI,S,C,I,A base;
    class E,RL,RC temporal;
    class CR,M env;
```

## Severity Scale

![Severity Gauge](/images/severity-gauge.png)

| Rating   | Score Range | Color   |
| -------- | ----------- | ------- |
| None     | 0.0         | Gray    |
| Low      | 0.1 – 3.9   | Green   |
| Medium   | 4.0 – 6.9   | Yellow  |
| High     | 7.0 – 8.9   | Orange  |
| Critical | 9.0 – 10.0  | Red     |

A numeric base score maps to exactly one rating band via `GetSeverity()`:

```mermaid
flowchart LR
    Score(["Base Score 0.0–10.0"]) --> D{Which band?}
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

::: tip v3.0 vs v3.1 — the score can differ for the same vector
The band boundaries above are identical across versions, but the underlying formulas are not. CVSS v3.1 introduced a defined **roundup** function and re-weighted a few values (e.g. `UI:R` = 0.62 in v3.1 vs 0.56 in v3.0). The toolkit reads the `CVSS:3.0` / `CVSS:3.1` prefix and applies the matching formula automatically — so always keep the version prefix on your vectors.
:::

## Quick Start

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
# Score a vector — works the same in every integration
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Output: 9.8 (Critical)
```

## Next Steps

- [Integration Methods](/integration/) — compare Skills, Go SDK, CLI, and MCP, with a decision tree
- [CLI Reference](/cli/) — all 30+ commands with examples
- [Downloads](/downloads/) — pre-built binaries for every OS/arch, with checksum verification
- [API Docs](/docs/api/) — the complete Go SDK reference
