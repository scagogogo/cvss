# parser Package

The `parser` package is responsible for parsing CVSS vector strings into structured data objects, supporting CVSS 3.0 and 3.1 formats.

## Package Overview

```go
import "github.com/scagogogo/cvss-skills/pkg/parser"
```

## Main Types

| Type | Description | Documentation Link |
|------|-------------|-------------------|
| `Cvss3xParser` | CVSS 3.x vector string parser | [Detailed Documentation](/api/parser/cvss3x-parser) |
| `VectorParser` | Generic vector parser interface | [Detailed Documentation](/api/parser/cvss3x-parser) |

## Quick Examples

### Basic Parsing

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Create parser
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    // Parse vector
    cvssVector, err := p.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }

    fmt.Printf("Parse successful: %s\n", cvssVector.String())
}
```

### 批量解析

```go
func parseVectors(vectorStrings []string) {
    for _, vectorStr := range vectorStrings {
        p := parser.NewCvss3xParser(vectorStr)
        cvssVector, err := p.Parse()
        if err != nil {
            fmt.Printf("解析失败 %s: %v\n", vectorStr, err)
            continue
        }
        
        fmt.Printf("✓ %s\n", cvssVector.String())
    }
}
```

## 支持的格式

### CVSS 3.0 格式
```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### CVSS 3.1 格式
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### 包含时间指标
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
```

### 包含环境指标
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:L/MAC:H
```

## 解析规则

### 1. 格式要求
- 必须以 `CVSS:` 开头
- 版本号格式：`3.0` 或 `3.1`
- 指标之间用 `/` 分隔
- 指标格式：`KEY:VALUE`

### 2. 必需指标
基础指标（必须全部存在）：
- `AV` - 攻击向量
- `AC` - 攻击复杂性
- `PR` - 所需权限
- `UI` - 用户交互
- `S` - 影响范围
- `C` - 机密性影响
- `I` - 完整性影响
- `A` - 可用性影响

### 3. 可选指标
时间指标：
- `E` - 漏洞利用代码成熟度
- `RL` - 修复级别
- `RC` - 报告可信度

环境指标：
- `CR`, `IR`, `AR` - 安全需求
- `MAV`, `MAC`, `MPR`, `MUI`, `MS` - 修改的基础指标
- `MC`, `MI`, `MA` - 修改的影响指标

## 错误处理

### 常见错误类型

```go
// 魔术头错误
ErrParserMagicHead = errors.New("cvss 3.x parser error, magic head valid, it must equals 'CVSS'")
```

### 错误示例

```go
// 无效的魔术头
p := parser.NewCvss3xParser("INVALID:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err := p.Parse()
// err: cvss 3.x parser error, magic head valid, it must equals 'CVSS'

// 无效的版本号
p = parser.NewCvss3xParser("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
_, err = p.Parse()
// err: invalid major version

// 缺少必需指标
p = parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L")
_, err = p.Parse()
// err: Privileges Required can not empty
```

## 解析流程

### 1. 词法分析
```go
// 分解向量字符串
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
↓
["CVSS", "3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H"]
```

### 2. 语法分析
```go
// 解析各个组件
"CVSS" → 魔术头验证
"3.1"  → 版本号解析 (major=3, minor=1)
"AV:N" → 指标解析 (key="AV", value="N")
```

### 3. 语义分析
```go
// 创建向量对象
"AV:N" → &vector.AttackVectorNetwork{}
"AC:L" → &vector.AttackComplexityLow{}
```

## 性能特性

### 解析性能
- **高效解析**: 单次遍历字符串
- **内存优化**: 最小化内存分配
- **错误快速失败**: 遇到错误立即返回

### 基准测试结果
```
BenchmarkCvss3xParser_Parse-8    1000000    1200 ns/op    480 B/op    12 allocs/op
```

## 扩展性

### 自定义向量解析
```go
// 实现 VectorParser 接口
type CustomParser struct {
    // 自定义字段
}

func (p *CustomParser) Parse(vectorStr string) (interface{}, error) {
    // 自定义解析逻辑
    return nil, nil
}
```

### 解析钩子
```go
// 解析前处理
func preprocessVector(vectorStr string) string {
    // 标准化处理
    return strings.ToUpper(strings.TrimSpace(vectorStr))
}

// 解析后处理
func postprocessVector(cvss *cvss.Cvss3x) error {
    // 自定义验证
    return cvss.Check()
}
```

## 最佳实践

### 1. 错误处理
```go
cvssVector, err := p.Parse()
if err != nil {
    // 记录详细错误信息
    log.Printf("解析CVSS向量失败: %s, 错误: %v", vectorStr, err)
    return fmt.Errorf("CVSS解析失败: %w", err)
}
```

### 2. 输入验证
```go
func parseWithValidation(vectorStr string) (*cvss.Cvss3x, error) {
    // 预处理
    vectorStr = strings.TrimSpace(vectorStr)
    if vectorStr == "" {
        return nil, fmt.Errorf("CVSS向量字符串不能为空")
    }
    
    // 解析
    p := parser.NewCvss3xParser(vectorStr)
    cvssVector, err := p.Parse()
    if err != nil {
        return nil, err
    }
    
    // 后验证
    if err := cvssVector.Check(); err != nil {
        return nil, fmt.Errorf("CVSS向量验证失败: %w", err)
    }
    
    return cvssVector, nil
}
```

### 3. 并发解析
```go
func parseConcurrently(vectorStrings []string) []*cvss.Cvss3x {
    results := make([]*cvss.Cvss3x, len(vectorStrings))
    var wg sync.WaitGroup
    
    for i, vectorStr := range vectorStrings {
        wg.Add(1)
        go func(index int, str string) {
            defer wg.Done()
            
            p := parser.NewCvss3xParser(str)
            if cvssVector, err := p.Parse(); err == nil {
                results[index] = cvssVector
            }
        }(i, vectorStr)
    }
    
    wg.Wait()
    return results
}
```

## 包结构

```
parser/
├── cvss3x_parser.go      # CVSS 3.x 解析器实现
├── vector_parser.go      # 通用向量解析器接口
└── parser_unit_test.go   # 单元测试
```

## 下一步

深入了解具体的解析器：

- 📖 [Cvss3xParser 详细文档](/api/parser/cvss3x-parser)
- 🔧 [VectorParser 接口](/api/parser/cvss3x-parser)
- 💡 [解析示例](/examples/parsing)
