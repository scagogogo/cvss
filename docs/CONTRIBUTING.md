# 贡献指南

感谢您对 CVSS 解析器库的兴趣！这个文档提供了帮助您贡献代码、报告问题和改进项目的指导。

## 开发前准备

1. 确保您安装了 Go 1.19 或更高版本
2. 克隆代码库并设置您的工作环境：
   ```bash
   git clone https://github.com/scagogogo/cvss.git
   cd cvss
   go mod download
   ```

## 代码规范

- 所有代码应保持良好的文档
- 新的功能应该包括测试
- 遵循标准的 Go 格式和命名规范

## 测试

提交代码前，确保您的更改通过所有测试:

```bash
make test       # 运行基本测试
make test-ci    # 运行 CI 级别的测试，包括运行示例
make coverage   # 生成测试覆盖率报告
```

## GitHub Actions 工作流程

本项目使用 GitHub Actions 来自动化测试和验证。每次代码提交到 main 分支或创建拉取请求时，GitHub Actions 都会：

1. 在不同版本的 Go 环境中运行单元测试
2. 编译所有示例代码
3. 运行基本示例程序
4. 生成测试覆盖率报告

### 本地测试 GitHub Actions 工作流程

您可以在提交代码前在本地测试 GitHub Actions 工作流：

#### 使用 act 工具

1. 安装 [act](https://github.com/nektos/act)：
   ```bash
   # MacOS
   brew install act
   
   # 其他系统请参考 act 仓库安装说明
   ```

2. 运行工作流：
   ```bash
   act -j test
   ```

#### 使用 Makefile

更简单的方法是使用我们的 `test-ci` Makefile 目标，它会执行与 GitHub Actions 相同的测试步骤：

```bash
make test-ci
```

## 提交流程

1. 创建一个新的分支用于您的功能或修复：
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. 进行更改并提交：
   ```bash
   git add .
   git commit -m "添加了新功能：简要描述"
   ```

3. 推送到您的分支：
   ```bash
   git push origin feature/your-feature-name
   ```

4. 创建一个拉取请求到 main 分支

## 报告问题

如果您发现问题或有功能请求，请使用 GitHub Issues 提交。请尽可能详细地描述问题，并提供重现步骤。

## 联系方式

如有任何问题，请联系项目维护者。 