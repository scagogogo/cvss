# CVSS 解析器

[![Go Tests and Examples](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cvss/actions/workflows/go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cvss)](https://goreportcard.com/report/github.com/scagogogo/cvss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CVSS 解析器是一个 Go 语言库，用于解析、计算和处理 CVSS (通用漏洞评分系统) 向量。支持 CVSS 3.0 和 3.1 版本，提供了全面的功能以满足漏洞管理和安全评估的需求。

## 特性

- 支持 CVSS 3.0 和 3.1 向量的解析和计算
- 计算基础、时间和环境评分
- 提供 JSON 输出和格式化功能
- 向量比较和相似度计算
- 严格模式和容错模式解析
- 完整的文档和示例
- 高测试覆盖率

## 安装

```bash
go get github.com/scagogogo/cvss
```

## 快速开始

解析和计算 CVSS 评分：

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    vectorString := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // 解析 CVSS 向量
    cvssVector, err := parser.ParseVector(vectorString)
    if err != nil {
        log.Fatalf("解析向量失败: %v", err)
    }
    
    // 计算 CVSS 评分
    score := cvssVector.Calculate()
    
    fmt.Printf("CVSS 评分: %.1f\n", score.BaseScore)
    fmt.Printf("严重性: %s\n", score.Severity)
}
```

更多示例请查看 [examples](./examples) 目录。详细的 API 文档请参考 [pkg.go.dev](https://pkg.go.dev/github.com/scagogogo/cvss).

## 示例

库包含一系列详细的示例，展示了不同的功能：

1. [基础用法](./examples/01_basic) - 基本的 CVSS 解析和评分计算
2. [解析不同类型的向量](./examples/02_parsing) - 展示如何解析各种 CVSS 向量字符串
3. [JSON 输出](./examples/03_json) - 将 CVSS 对象转换为 JSON 格式
4. [时间度量指标](./examples/04_temporal) - 使用时间度量指标及其评分影响
5. [环境度量指标](./examples/05_environmental) - 使用环境度量指标及其评分影响
6. [向量距离计算](./examples/06_distance) - 计算两个 CVSS 向量之间的距离
7. [向量比较](./examples/07_vector_comparison) - 比较 CVSS 向量的方法
8. [严重性级别](./examples/08_severity_levels) - 处理 CVSS 严重性级别
9. [边缘案例](./examples/09_edge_cases) - 管理各种边缘情况

## 持续集成

本项目使用 GitHub Actions 自动运行测试和验证示例代码。CI 流程包括：

- 在多个 Go 版本 (1.19, 1.20, 1.21) 上运行测试
- 捕获和上传测试覆盖率报告
- 编译所有示例代码以确保它们能正确构建
- 运行基本示例以验证功能

您可以在本地运行相同的测试：

```bash
make test-ci
```

## 贡献

欢迎贡献代码、报告问题和提出改进建议！请查看 [贡献指南](./docs/CONTRIBUTING.md) 了解更多信息。

## 许可证

本项目基于 MIT 许可证 - 详情请参见 [LICENSE](LICENSE) 文件。





