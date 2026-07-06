# 贡献指南

感谢您对 CVSS Skills 项目的兴趣！本指南将帮助您了解如何为项目做出贡献。

## 概述

CVSS Skills 是一个用于解析和计算 CVSS 3.x 向量的 Go 库。我们欢迎各种形式的贡献，包括：

- 错误报告
- 功能请求
- 代码贡献
- 文档改进
- 测试用例
- 性能优化

## 开发环境设置

### 先决条件

- Go 1.19 或更高版本
- Git
- Make (可选，用于构建脚本)

### 设置步骤

1. **Fork 仓库**
   ```bash
   # 在 GitHub 上 fork 仓库，然后克隆您的 fork
   git clone https://github.com/YOUR_USERNAME/cvss-skills.git
   cd cvss-skills
   ```

2. **添加上游远程**
   ```bash
   git remote add upstream https://github.com/scagogogo/cvss-skills.git
   ```

3. **安装依赖**
   ```bash
   go mod download
   ```

4. **运行测试**
   ```bash
   go test ./...
   # 或使用 Makefile：
   make test
   ```

   本项目对 `pkg/...` 强制要求 **100% 测试覆盖率**，所有贡献必须维持该门槛：
   ```bash
   make coverage-check   # CI 会强制执行
   ```

5. **构建项目**
   ```bash
   go build ./...
   ```

## 开发工作流

### 分支策略

- `main` - 主分支，包含稳定代码
- `develop` - 开发分支，用于集成新功能
- `feature/*` - 功能分支
- `bugfix/*` - 错误修复分支
- `hotfix/*` - 紧急修复分支

### 创建功能分支

```bash
# 从最新的 main 分支创建功能分支
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

### 提交消息规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**类型:**
- `feat`: 新功能
- `fix`: 错误修复
- `docs`: 文档更改
- `style`: 代码格式更改
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建过程或辅助工具的变动

**示例:**
```
feat(parser): add support for CVSS 4.0 vectors

Add parsing capability for CVSS 4.0 vector strings including
new metrics and updated calculation formulas.

Closes #123
```

## 代码标准

### Go 代码风格

遵循标准的 Go 代码风格：

1. **格式化**
   ```bash
   go fmt ./...
   ```

2. **Linting**
   ```bash
   golangci-lint run
   ```

3. **命名约定**
   - 包名：小写，简短，描述性
   - 函数名：驼峰命名法
   - 常量：大写，下划线分隔
   - 接口：以 -er 结尾（如 Parser, Calculator）

### 代码组织

```
pkg/
├── cvss/           # 核心 CVSS 功能
│   ├── calculator.go
│   ├── cvss3x.go
│   └── distance.go
├── parser/         # 解析器实现
│   └── cvss3x_parser.go
└── vector/         # 向量接口和实现
    ├── interface.go
    └── metrics.go
```

### 错误处理

```go
// 好的错误处理
func ParseVector(vectorStr string) (*Cvss3x, error) {
    if vectorStr == "" {
        return nil, fmt.Errorf("vector string cannot be empty")
    }
    
    // ... 解析逻辑
    
    if err != nil {
        return nil, fmt.Errorf("failed to parse vector: %w", err)
    }
    
    return vector, nil
}

// 避免的做法
func ParseVector(vectorStr string) *Cvss3x {
    // 不要忽略错误或使用 panic
    vector, _ := parse(vectorStr)
    return vector
}
```

### 文档注释

```go
// Calculator 提供 CVSS 分数计算功能。
// 它支持基础、时间和环境分数计算。
type Calculator struct {
    vector *Cvss3x
}

// Calculate 计算 CVSS 向量的最终分数。
// 如果向量包含时间或环境指标，它们将被包含在计算中。
//
// 返回值在 0.0 到 10.0 之间。
func (c *Calculator) Calculate() (float64, error) {
    // 实现...
}
```

## 测试

### 测试策略

1. **单元测试** - 测试单个函数和方法
2. **集成测试** - 测试组件之间的交互
3. **基准测试** - 性能测试

### 编写测试

```go
func TestCalculator_Calculate(t *testing.T) {
    tests := []struct {
        name     string
        vector   string
        expected float64
        wantErr  bool
    }{
        {
            name:     "高严重性向量",
            vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expected: 9.8,
            wantErr:  false,
        },
        {
            name:     "无效向量",
            vector:   "INVALID",
            expected: 0,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            parser := parser.NewCvss3xParser(tt.vector)
            vector, err := parser.Parse()
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            
            require.NoError(t, err)
            
            calc := NewCalculator(vector)
            score, err := calc.Calculate()
            
            require.NoError(t, err)
            assert.InDelta(t, tt.expected, score, 0.1)
        })
    }
}
```

### 运行测试

```bash
# 运行所有测试（4 个包）
go test ./...
# 或使用 Makefile：
make test

# 强制 100% 覆盖率门槛（CI 要求）
make coverage-check

# 生成 HTML 覆盖率报告
make coverage

# 运行特定包的测试
go test ./pkg/cvss
go test ./pkg/parser
go test ./pkg/vector
go test ./pkg/mock

# 运行 lint（与 CI 一致）
make lint

# 运行基准测试
go test -bench=. ./...
```

## 文档

### 文档结构

```
docs/
├── api/                # API 参考文档
│   ├── cvss/
│   ├── parser/
│   └── vector/
├── examples/           # 使用示例
├── zh/                 # 中文文档
└── README.md
```

### 文档编写指南

1. **清晰简洁** - 使用简单明了的语言
2. **代码示例** - 提供实际可运行的示例
3. **完整性** - 覆盖所有公共 API
4. **更新及时** - 与代码变更保持同步

### 构建文档

```bash
# 安装 VitePress
npm install

# 本地开发
npm run docs:dev

# 构建文档
npm run docs:build
```

## 提交 Pull Request

### PR 检查清单

在提交 PR 之前，请确保：

- [ ] 代码遵循项目风格指南
- [ ] 所有测试通过
- [ ] 添加了适当的测试用例
- [ ] 更新了相关文档
- [ ] 提交消息遵循约定格式
- [ ] PR 描述清楚说明了变更内容

### PR 模板

```markdown
## 变更描述
简要描述此 PR 的变更内容。

## 变更类型
- [ ] 错误修复
- [ ] 新功能
- [ ] 重大变更
- [ ] 文档更新
- [ ] 性能改进
- [ ] 其他

## 测试
描述您如何测试了这些变更。

## 检查清单
- [ ] 我的代码遵循项目的风格指南
- [ ] 我已经进行了自我代码审查
- [ ] 我已经添加了适当的注释
- [ ] 我的变更生成了新的警告
- [ ] 我已经添加了证明我的修复有效或功能正常的测试
- [ ] 新的和现有的单元测试在我的变更下都通过了
- [ ] 任何依赖的变更都已经合并和发布
```

## 发布流程

### 版本控制

使用 [Semantic Versioning](https://semver.org/)：

- `MAJOR.MINOR.PATCH`
- `MAJOR`: 不兼容的 API 变更
- `MINOR`: 向后兼容的功能添加
- `PATCH`: 向后兼容的错误修复

### 发布步骤

1. **更新版本号**
2. **更新 CHANGELOG**
3. **创建 Git 标签**
4. **发布到 GitHub**

## 社区

### 沟通渠道

- **GitHub Issues** - 错误报告和功能请求
- **GitHub Discussions** - 一般讨论和问题
- **Pull Requests** - 代码审查和讨论

### 行为准则

我们致力于为每个人提供友好、安全和欢迎的环境。请：

- 使用友好和包容的语言
- 尊重不同的观点和经验
- 优雅地接受建设性批评
- 专注于对社区最有利的事情
- 对其他社区成员表现出同理心

## 常见问题

### Q: 如何报告安全漏洞？
A: 请通过私人渠道联系维护者，不要在公共 issue 中报告安全问题。

### Q: 我可以添加对 CVSS 2.0 的支持吗？
A: 目前项目专注于 CVSS 3.x。CVSS 2.0 支持可能在未来考虑。

### Q: 如何提出新功能建议？
A: 请在 GitHub Issues 中创建功能请求，详细描述用例和预期行为。

### Q: 代码审查需要多长时间？
A: 我们努力在 48 小时内进行初始审查，但复杂的 PR 可能需要更长时间。

## 致谢

感谢所有为 CVSS Skills 项目做出贡献的开发者！

## 许可证

通过贡献代码，您同意您的贡献将在与项目相同的许可证下授权。

---

如果您有任何问题或需要帮助，请随时在 GitHub Issues 中提问或联系维护者。我们很乐意帮助新贡献者开始！
