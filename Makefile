.PHONY: build clean test run

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

# 帮助
help:
	@echo "CVSS Parser Makefile Help"
	@echo ""
	@echo "make             - Build the program"
	@echo "make build       - Build the program"
	@echo "make test        - Run tests"
	@echo "make run ARGS='...' - Run the program with arguments"
	@echo "   Example: make run ARGS='-v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -detailed'"
	@echo "make clean       - Remove build artifacts"
	@echo "make install     - Install to GOPATH/bin" 