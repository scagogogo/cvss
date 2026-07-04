---
title: CVSS Metrics Overview
description: The three CVSS metric groups (Base, Temporal, Environmental), the vector string structure, and how each metric feeds into the final score.
---

# 📊 CVSS Metrics Overview

🧮 Scoring · 📐 Base + Temporal + Environmental

A CVSS v3.x vector string is a sequence of metric short-names and values. Every metric belongs to one of three groups. The Base group captures the intrinsic qualities of the vulnerability; the Temporal group reflects how the vulnerability evolves over time; the Environmental group tailors the score to a specific deployment.

## Metric Groups

```mermaid
flowchart LR
    subgraph Base["Base Metrics (8)"]
        AV["AV Attack Vector"]
        AC["AC Attack Complexity"]
        PR["PR Privileges Required"]
        UI["UI User Interaction"]
        S["S Scope"]
        C["C Confidentiality"]
        I["I Integrity"]
        A["A Availability"]
    end
    subgraph Temporal["Temporal Metrics (3)"]
        E["E Exploit Code Maturity"]
        RL["RL Remediation Level"]
        RC["RC Report Confidence"]
    end
    subgraph Environmental["Environmental Metrics (11)"]
        CR["CR Confidentiality Req."]
        IR["IR Integrity Req."]
        AR["AR Availability Req."]
        MAV["MAV Modified AV"]
        MAC["MAC Modified AC"]
        MPR["MPR Modified PR"]
        MUI["MUI Modified UI"]
        MS["MS Modified Scope"]
        MC["MC Modified C"]
        MI["MI Modified I"]
        MA["MA Modified A"]
    end
    Base --> Temporal
    Temporal --> Environmental
```

The score is computed left to right: **Base Score → Temporal Score → Environmental Score**. Each later stage multiplies the previous score by its metric factors, so the Environmental Score is always the most specific (and final) number.

## All Metrics

| Short Name | Long Name              | Group         | # Values |
| ---------- | ---------------------- | ------------- | -------- |
| AV         | Attack Vector          | Base          | 4        |
| AC         | Attack Complexity      | Base          | 2        |
| PR         | Privileges Required    | Base          | 3        |
| UI         | User Interaction       | Base          | 2        |
| S          | Scope                  | Base          | 2        |
| C          | Confidentiality        | Base          | 3        |
| I          | Integrity              | Base          | 3        |
| A          | Availability           | Base          | 3        |
| E          | Exploit Code Maturity  | Temporal      | 5        |
| RL         | Remediation Level      | Temporal      | 5        |
| RC         | Report Confidence      | Temporal      | 4        |
| CR         | Confidentiality Req.   | Environmental | 4        |
| IR         | Integrity Requirement  | Environmental | 4        |
| AR         | Availability Req.      | Environmental | 4        |
| MAV        | Modified Attack Vector | Environmental | 5        |
| MAC        | Modified Attack Complexity | Environmental | 5 |
| MPR        | Modified Privileges Required | Environmental | 5 |
| MUI        | Modified User Interaction | Environmental | 5    |
| MS         | Modified Scope         | Environmental | 3        |
| MC         | Modified Confidentiality | Environmental | 5      |
| MI         | Modified Integrity    | Environmental | 5        |
| MA         | Modified Availability | Environmental | 5        |

## Vector String Structure

A vector string starts with the CVSS version prefix, followed by metric pairs in a fixed order:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

- `CVSS:3.1` — version prefix (`3.0` or `3.1`).
- Base metrics come first, in the order **AV / AC / PR / UI / S / C / I / A**.
- Temporal metrics follow: **E / RL / RC** (all optional).
- Environmental metrics come last: **CR / IR / AR / MAV / MAC / MPR / MUI / MS / MC / MI / MA** (all optional).
- Each pair is `SHORT_NAME:VALUE`. The `X` value means "Not Defined" and tells the scorer to fall back to the base value.

Temporal and Environmental metrics are optional. When omitted, the scorer applies their default (`X` / Not Defined) behaviour, which leaves the previous score unchanged.

## Scoring Pipeline

1. **Base Score** — computed from the 8 Base metrics. It never changes for a given vulnerability.
2. **Temporal Score** — `Base × E × RL × RC`. Each temporal metric is a multiplier; `X` (Not Defined) acts as `1` (no change).
3. **Environmental Score** — applies the requirement weights (CR/IR/AR) and the Modified metrics (M*) to refine the result for a specific environment.

Use the CLI to see all three at once:

```bash
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:H"
```

```text
Base: 10.0 (Critical), Temporal: 9.4 (Critical), Environmental: 9.7 (Critical)
```

## Per-Metric Pages

### Base Metrics

- [Attack Vector (AV)](./attack-vector)
- [Attack Complexity (AC)](./attack-complexity)
- [Privileges Required (PR)](./privileges-required)
- [User Interaction (UI)](./user-interaction)
- [Scope (S)](./scope)
- [Confidentiality (C)](./confidentiality)
- [Integrity (I)](./integrity)
- [Availability (A)](./availability)

### Temporal Metrics

- [Exploit Code Maturity (E)](./exploit-code-maturity)
- [Remediation Level (RL)](./remediation-level)
- [Report Confidence (RC)](./report-confidence)

### Environmental Metrics

- [Requirements (CR/IR/AR)](./requirements)
- [Modified Metrics (M*)](./modified)

## Source

The metric definitions and scores live in [`pkg/vector/`](https://github.com/scagogogo/cvss-skills/tree/main/pkg/vector). Each metric is its own `.go` file exposing preset variables and, where needed, a version/scope-aware score helper.

## Related

- [SDK: vector package](../sdk/vector)
- [CLI: score command](../cli/commands/score)
- [Concepts: scoring](../concepts/scoring)
