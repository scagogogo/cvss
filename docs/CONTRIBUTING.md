# Contributing Guide

Thank you for your interest in the CVSS Skills library! This document provides guidance on how to contribute code, report issues, and improve the project.

## Development Setup

1. Ensure you have Go 1.19 or higher installed
2. Clone the repository and set up your development environment:
   ```bash
   git clone https://github.com/scagogogo/cvss-skills.git
   cd cvss
   go mod download
   ```

## Code Standards

- All code should be well-documented
- New features should include tests
- Follow standard Go formatting and naming conventions
- Use `gofmt` and `golint` to ensure code quality
- Write clear commit messages

## Development Workflow

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/cvss.git
cd cvss

# Add the original repository as upstream
git remote add upstream https://github.com/scagogogo/cvss-skills.git
```

### 2. Create a Feature Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 3. Make Changes

- Write your code following the project conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Test Your Changes

This project enforces **100% test coverage** on `pkg/...`. All contributions must maintain this threshold.

```bash
# Run all tests (4 packages)
go test ./...
# or via Makefile:
make test

# Enforce 100% coverage threshold (CI requires this)
make coverage-check

# Generate an HTML coverage report
make coverage

# Run specific package tests
go test ./pkg/parser
go test ./pkg/cvss
go test ./pkg/vector
go test ./pkg/mock

# Lint (same as CI)
make lint

# Run benchmarks
go test -bench=. ./...
```

### 5. Commit and Push

```bash
# Stage your changes
git add .

# Commit with a descriptive message
git commit -m "feat: add support for CVSS 4.0 parsing"

# Push to your fork
git push origin feature/your-feature-name
```

### 6. Create Pull Request

1. Go to the GitHub repository
2. Click "New Pull Request"
3. Select your branch
4. Fill out the PR template
5. Submit for review

## Code Style Guidelines

### Go Code Style

```go
// Good: Clear function names and documentation
// ParseCVSSVector parses a CVSS vector string and returns a structured object.
func ParseCVSSVector(vectorStr string) (*Cvss3x, error) {
    if vectorStr == "" {
        return nil, fmt.Errorf("vector string cannot be empty")
    }
    
    parser := NewCvss3xParser(vectorStr)
    return parser.Parse()
}

// Good: Proper error handling
func (p *Parser) parseMetric(metric string) error {
    if metric == "" {
        return fmt.Errorf("metric cannot be empty")
    }
    
    // Parse logic here
    return nil
}
```

### Documentation Style

```go
// Package parser provides CVSS vector string parsing functionality.
//
// This package supports parsing CVSS 3.0 and 3.1 vector strings into
// structured data objects that can be used for score calculation and analysis.
//
// Example usage:
//   parser := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
//   vector, err := parser.Parse()
//   if err != nil {
//       log.Fatal(err)
//   }
package parser
```

### Test Style

```go
func TestCvss3xParser_Parse(t *testing.T) {
    tests := []struct {
        name        string
        vectorStr   string
        expectError bool
        expected    *Cvss3x
    }{
        {
            name:        "valid basic vector",
            vectorStr:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            expectError: false,
            expected:    &Cvss3x{/* expected values */},
        },
        {
            name:        "invalid vector format",
            vectorStr:   "INVALID",
            expectError: true,
            expected:    nil,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            parser := NewCvss3xParser(tt.vectorStr)
            result, err := parser.Parse()

            if tt.expectError {
                assert.Error(t, err)
                assert.Nil(t, result)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, result)
                // Add specific assertions for expected values
            }
        })
    }
}
```

## Types of Contributions

### 🐛 Bug Reports

When reporting bugs, please include:

1. **Clear description** of the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs actual behavior
4. **Environment details** (Go version, OS, etc.)
5. **Code sample** that demonstrates the issue

Example bug report:
```markdown
## Bug Description
Parser fails to handle CVSS vectors with environmental metrics

## Steps to Reproduce
1. Create parser with vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H"
2. Call Parse() method
3. Observe error

## Expected Behavior
Parser should successfully parse the vector

## Actual Behavior
Parser returns error: "unknown metric CR"

## Environment
- Go version: 1.19
- OS: macOS 12.0
- CVSS Skills version: v1.0.0
```

### ✨ Feature Requests

For new features, please provide:

1. **Use case description** - Why is this needed?
2. **Proposed solution** - How should it work?
3. **Alternative solutions** - What other approaches were considered?
4. **Implementation details** - Any technical considerations

### 🔧 Code Contributions

We welcome contributions for:

- **New CVSS version support** (e.g., CVSS 4.0)
- **Performance improvements**
- **Additional distance algorithms**
- **Better error messages**
- **Documentation improvements**
- **Test coverage improvements**

### 📚 Documentation Contributions

Help improve documentation by:

- **Adding examples** for complex use cases
- **Improving API documentation**
- **Fixing typos and grammar**
- **Translating documentation**
- **Adding tutorials**

## Testing Guidelines

### Unit Tests

```bash
# Run all unit tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test ./pkg/parser

# Run specific test
go test -run TestCvss3xParser_Parse ./pkg/parser
```

### Integration Tests

```bash
# Run integration tests (if any)
go test -tags=integration ./...
```

### Benchmark Tests

```bash
# Run all benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkParser ./pkg/parser

# Run benchmarks with memory profiling
go test -bench=. -benchmem ./...
```

### Coverage Reports

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Show coverage summary
go tool cover -func=coverage.out
```

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Release Checklist

1. Update version numbers
2. Update CHANGELOG.md
3. Run full test suite
4. Update documentation
5. Create release tag
6. Publish release notes

## Code Review Process

### For Contributors

1. **Self-review** your code before submitting
2. **Write clear PR descriptions** explaining the changes
3. **Respond promptly** to review feedback
4. **Keep PRs focused** - one feature/fix per PR

### Review Criteria

We review for:

- **Correctness** - Does the code work as intended?
- **Performance** - Are there any performance implications?
- **Security** - Are there any security concerns?
- **Maintainability** - Is the code easy to understand and modify?
- **Testing** - Are there adequate tests?
- **Documentation** - Is the code properly documented?

## Community Guidelines

### Code of Conduct

- **Be respectful** and inclusive
- **Be constructive** in feedback
- **Be patient** with newcomers
- **Be collaborative** in problem-solving

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and discussions
- **Pull Requests** - Code contributions and reviews

## Getting Help

If you need help contributing:

1. **Check existing issues** and documentation
2. **Ask questions** in GitHub Discussions
3. **Join community discussions**
4. **Reach out to maintainers** if needed

## Recognition

Contributors are recognized through:

- **Contributor list** in README
- **Release notes** acknowledgments
- **GitHub contributor graphs**
- **Special thanks** for significant contributions

Thank you for contributing to CVSS Skills! 🎉
