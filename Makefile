.PHONY: build clean test run test-ci coverage

# 默认目标
all: build

# 编译
build:
	@echo "Building cvss-cli..."
	@go build -o bin/cvss-cli cmd/cvss-cli/main.go

# 运行测试
test:
	@echo "Running tests..."
	@go test ./pkg/cvss ./pkg/parser ./pkg/vector

# 运行程序
run:
	@echo "Running cvss-cli..."
	@./bin/cvss-cli $(ARGS)

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf bin/

# 安装
install:
	@echo "Installing cvss-cli..."
	@go install ./cmd/cvss-cli

# CI测试 (与GitHub Action相同的测试)
test-ci:
	@echo "Running CI tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./pkg/...
	@echo "Building all examples..."
	@find ./examples -type f -name "main.go" -exec dirname {} \; | while read dir; do \
		echo "Building example: $$dir"; \
		go build -o /dev/null $$dir; \
	done
	@echo "Running basic examples..."
	@go run ./examples/01_basic/main.go
	@go run ./examples/02_parsing/main.go
	@go run ./examples/03_json/main.go

# 覆盖率报告
coverage:
	@echo "Generating coverage report..."
	@go test -coverprofile=coverage.txt -covermode=atomic ./pkg/...
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report saved to coverage.html"

# 帮助
help:
	@echo "CVSS Parser Makefile Help"
	@echo ""
	@echo "make             - Build the program"
	@echo "make build       - Build the program"
	@echo "make test        - Run tests"
	@echo "make test-ci     - Run CI tests (same as GitHub Action)"
	@echo "make coverage    - Generate coverage report"
	@echo "make run ARGS='...' - Run the program with arguments"
	@echo "   Example: make run ARGS='-v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -detailed'"
	@echo "make clean       - Remove build artifacts"
	@echo "make install     - Install to GOPATH/bin" 