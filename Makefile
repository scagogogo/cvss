.PHONY: build clean test run test-ci coverage coverage-check lint

# 默认目标
all: build

# 编译
build:
	@echo "Building cvss-cli..."
	@go build -o bin/cvss-cli ./cmd/cvss-cli/

# 运行测试（4 个 pkg 包 + CLI）
test:
	@echo "Running tests..."
	@go test ./pkg/... ./cmd/...

# 运行程序
run:
	@echo "Running cvss-cli..."
	@./bin/cvss-cli $(ARGS)

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf bin/ coverage.txt coverage.html coverage.xml

# 安装
install:
	@echo "Installing cvss-cli..."
	@go install ./cmd/cvss-cli

# CI测试 (与GitHub Action相同的测试)
test-ci:
	@echo "Running CI tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./pkg/...
	@go test -v -race ./cmd/...
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
	@go tool cover -func=coverage.txt | tail -1
	@echo "Coverage report saved to coverage.html"

# 覆盖率门槛检查（要求 100%）
coverage-check:
	@echo "Checking coverage threshold (100%)..."
	@go test -coverprofile=coverage.txt -covermode=atomic ./pkg/... >/dev/null 2>&1
	@total=$$(go tool cover -func=coverage.txt | tail -1 | awk '{print $$NF}' | tr -d '%' ); \
	if [ "$$total" = "100.0" ]; then \
		echo "Coverage is 100.0% - threshold met"; \
	else \
		echo "Coverage is $$total% - below 100% threshold" >&2; \
		rm -f coverage.txt; \
		exit 1; \
	fi
	@rm -f coverage.txt

# 代码检查
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run --timeout=5m ./...

# 帮助
help:
	@echo "CVSS Skills Makefile Help"
	@echo ""
	@echo "make                 - Build the program"
	@echo "make build           - Build the program"
	@echo "make test            - Run all unit tests (pkg/... and cmd/...)"
	@echo "make test-ci         - Run CI tests (same as GitHub Action)"
	@echo "make coverage        - Generate HTML coverage report"
	@echo "make coverage-check  - Enforce 100% coverage threshold"
	@echo "make lint            - Run golangci-lint"
	@echo "make run ARGS='...'  - Run the program with arguments"
	@echo "   Example: make run ARGS='score CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H --format json'"
	@echo "make clean           - Remove build artifacts and coverage files"
	@echo "make install         - Install to GOPATH/bin" 