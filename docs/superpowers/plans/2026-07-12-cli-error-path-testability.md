# CLI 错误路径可测化与测试覆盖 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 `die`/`dief` 中的 `os.Exit(1)` 可测化(注入可替换的 `exitFunc`),并为 CLI 的 invalid-input 错误分支补充测试,解锁当前因进程被杀而完全 0% 覆盖的错误路径。

**Architecture:** 现有 `die`/`dief`(helpers.go)内部直接 `os.Exit(1)`,导致 46 个 `dief` 调用点 + 13 个直接 `os.Exit` 调用所在的错误分支在测试中一旦命中就杀进程,`runCommand` 的 `Execute()` 永远返回 nil,无法断言错误输出。改造:把 `os.Exit(1)` 替换为包级变量 `exitFunc func(code int)` 的调用,默认值 `func(code int) { os.Exit(code) }`(生产行为零变化);测试时注入一个 `panic` 版本,`runCommandExpectError` 辅助函数用 `recover` 捕获并断言 stderr 输出含预期错误关键词。新增覆盖 parse 错误(score/parse/describe 等命令的无效向量)、preset 未知 severity、build 缺指标等错误分支。

**Tech Stack:** Go 1.25, cobra, `os.Pipe` + `recover`,现有 `runCommand`/`resetFlags` 测试基础设施

**Risks:**
- T1 修改 `die`/`dief` 是 30 个命令文件共用的核心基础设施 → 缓解:函数签名与对外行为完全不变,仅把 `os.Exit(1)` 这一行替换为 `exitFunc(1)`;`exitFunc` 默认值就是 `os.Exit`,生产二进制行为零变化(用 `/tmp/cvss score INVALID` 实测对照)
- `exitFunc` 是包级变量,测试间残留(同 [[cli-test-flag-state-pollution]]) → 缓解:`runCommandExpectError` 用 `defer` 还原 `exitFunc` 到默认值,且与 `resetFlags()` 一并调用
- 注入 panic 后 `dief` 已先 `fmt.Fprintf(os.Stderr, ...)`,需同时 pipe stderr 才能断言输出 → 缓解:`runCommandExpectError` 同时 pipe stdout+stderr 到同一 buffer

---

### Task 1: 可测化 die/dief — 注入可替换的 exitFunc

**Depends on:** None
**Files:**
- Modify: `cmd/cvss-cli/helpers.go:13-23`(`die`/`dief` 函数体)
- Modify: `cmd/cvss-cli/helpers.go`(新增 `exitFunc` 变量声明,放在 `die` 之前)

- [ ] **Step 1: 修改 helpers.go 以新增 exitFunc 变量并替换 os.Exit 调用 — 让退出行为可被测试注入**

文件: `cmd/cvss-cli/helpers.go:13-23`(替换 `die` 与 `dief` 两个函数,并在它们之前插入 `exitFunc` 声明)

```go
// exitFunc terminates the process with the given exit code. It is a package-level
// variable so tests can substitute it (e.g. with a panic) to exercise error paths
// that normally call os.Exit and would otherwise kill the test process.
//
// Production code MUST NOT reassign exitFunc; only the test harness does.
var exitFunc = func(code int) {
	os.Exit(code)
}

// die prints msg to stderr and exits with code 1.
func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	exitFunc(1)
}

// dief prints a formatted message to stderr and exits with code 1.
func dief(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	exitFunc(1)
}
```

- [ ] **Step 2: 验证生产行为零变化 — 构建并对照错误输出与退出码**

Run: `go build -o /tmp/cvss ./cmd/cvss-cli/ && /tmp/cvss score "INVALID" 2>&1; echo "EXIT=$?"`
Expected:
  - Exit code: 0(build 阶段);score 子命令 EXIT=1
  - Output contains: `Parse error: cvss 3.x parser error: invalid magic head`

- [ ] **Step 3: 验证现有测试不受影响 — 全量回归**
Run: `go test ./cmd/cvss-cli/ 2>&1 | tail -3`
Expected:
  - Exit code: 0
  - Output contains: `ok` (37 个测试仍全过,因为测试不命中 die/dief 路径)

- [ ] **Step 4: 提交**
Run: `git add cmd/cvss-cli/helpers.go && git commit -m "refactor(cli): make die/dief exit injectable for error-path testing"`

---

### Task 2: 添加错误路径测试辅助函数与 parse 错误测试

**Depends on:** Task 1
**Files:**
- Modify: `cmd/cvss-cli/cli_smoke_test.go`(在 `runCommandWithStdin` 函数之后插入 `runCommandExpectError` 和相关测试)

- [ ] **Step 1: 修改 cli_smoke_test.go 以追加 runCommandExpectError 辅助函数 — 捕获错误路径的 stderr 并断言**

文件: `cmd/cvss-cli/cli_smoke_test.go`(在 `runCommandWithStdin` 函数末尾 `return buf.String()` 闭合之后、`TestVersionFlag` 之前插入)

```go
// runCommandExpectError runs the root command with args that are expected to
// trigger a die/dief error path. It substitutes exitFunc with a panic-on-call
// so the error path can be recovered instead of killing the test process,
// captures combined stdout+stderr, and returns the captured output.
//
// The test fails if the command does NOT trigger an exit (i.e. completes
// normally), because that means the error path was not exercised as intended.
func runCommandExpectError(t *testing.T, args ...string) string {
	t.Helper()

	// Reset flag state left over from prior tests (see resetFlags).
	resetFlags()

	// Substitute exitFunc so die/dief panic instead of killing the process.
	// The panic carries an exit-code sentinel so we can distinguish an
	// intentional exit from an unexpected panic.
	origExit := exitFunc
	exitFunc = func(code int) { panic(struct{ code int }{code}) }
	defer func() { exitFunc = origExit }()

	origOut := os.Stdout
	origErr := os.Stderr
	// Use a single pipe for combined stdout+stderr so die/dief's Fprintf to
	// os.Stderr is captured alongside cobra's own output.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	os.Stderr = w

	silenced := rootCmd.SilenceErrors
	rootCmd.SilenceErrors = true
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)

	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(copyDone)
	}()

	exited := false
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				// An exit was triggered — this is the expected error path.
				exited = true
			}
		}()
		_ = rootCmd.Execute()
	}()

	os.Stdout = origOut
	os.Stderr = origErr
	w.Close()
	<-copyDone
	r.Close()

	rootCmd.SilenceErrors = silenced
	rootCmd.SetArgs(nil)

	if !exited {
		t.Fatalf("expected error exit for args %v, but command completed normally; output: %q", args, buf.String())
	}
	return buf.String()
}
```

- [ ] **Step 2: 修改 cli_smoke_test.go 以追加 parse 错误路径测试 — 覆盖 score 命令的无效向量分支**

文件: `cmd/cvss-cli/cli_smoke_test.go`(在 `runCommandExpectError` 函数之后、`TestVersionFlag` 之前插入)

```go
// TestScoreCommand_InvalidVector verifies the score command's parse-error
// branch: an invalid vector triggers dief("Parse error: ...") rather than
// producing a score.
func TestScoreCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "score", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("invalid-vector output missing 'Parse error': %q", out)
	}
	if !strings.Contains(out, "invalid magic head") {
		t.Errorf("invalid-vector output missing 'invalid magic head': %q", out)
	}
}

// TestParseCommand_InvalidVector verifies the parse command's parse-error branch.
func TestParseCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "parse", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("invalid-vector output missing 'Parse error': %q", out)
	}
}
```

- [ ] **Step 3: 验证 parse 错误测试通过**
Run: `go test -run 'TestScoreCommand_InvalidVector|TestParseCommand_InvalidVector' ./cmd/cvss-cli/ -v`
Expected:
  - Exit code: 0
  - Output contains: `--- PASS: TestScoreCommand_InvalidVector`
  - Output contains: `--- PASS: TestParseCommand_InvalidVector`

- [ ] **Step 4: 提交**
Run: `git add cmd/cvss-cli/cli_smoke_test.go && git commit -m "test(cli): add error-path harness and parse-error tests"`

---

### Task 3: 扩展业务错误路径测试与全量回归

**Depends on:** Task 2
**Files:**
- Modify: `cmd/cvss-cli/cli_smoke_test.go`(在 Task 2 追加的测试之后插入更多错误路径测试)

- [ ] **Step 1: 修改 cli_smoke_test.go 以追加 preset/build/describe 错误路径测试 — 覆盖更多 dief 分支**

文件: `cmd/cvss-cli/cli_smoke_test.go`(在 `TestParseCommand_InvalidVector` 之后插入)

```go
// TestPresetCommand_UnknownSeverity verifies preset rejects an unknown severity.
func TestPresetCommand_UnknownSeverity(t *testing.T) {
	out := runCommandExpectError(t, "preset", "bogus")
	if !strings.Contains(out, "Unknown severity") {
		t.Errorf("preset output missing 'Unknown severity': %q", out)
	}
	if !strings.Contains(out, "bogus") {
		t.Errorf("preset output should echo the bad value 'bogus': %q", out)
	}
}

// TestBuildCommand_InvalidMetricValue verifies build rejects an invalid metric
// value (dief "Build error").
func TestBuildCommand_InvalidMetricValue(t *testing.T) {
	out := runCommandExpectError(t, "build",
		"--AV", "Z", // Z is not a valid AttackVector value
		"--AC", "L", "--PR", "N", "--UI", "N",
		"--S", "U", "--C", "H", "--I", "H", "--A", "H",
	)
	if !strings.Contains(out, "Build error") {
		t.Errorf("build output missing 'Build error': %q", out)
	}
}

// TestDescribeCommand_InvalidVector verifies describe's parse-error branch.
func TestDescribeCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "describe", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("describe output missing 'Parse error': %q", out)
	}
}

// TestGetCommand_InvalidVector verifies get's parse-error branch.
func TestGetCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "get", "INVALID", "AV")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("get output missing 'Parse error': %q", out)
	}
}

// TestSeverityCommand_InvalidScore verifies severity rejects a non-numeric score.
func TestSeverityCommand_InvalidScore(t *testing.T) {
	out := runCommandExpectError(t, "severity", "not-a-number")
	if !strings.Contains(out, "Invalid score") {
		t.Errorf("severity output missing 'Invalid score': %q", out)
	}
}
```

- [ ] **Step 2: 验证新增错误路径测试全部通过**
Run: `go test -run 'TestPresetCommand_UnknownSeverity|TestBuildCommand_InvalidMetricValue|TestDescribeCommand_InvalidVector|TestGetCommand_InvalidVector|TestSeverityCommand_InvalidScore' ./cmd/cvss-cli/ -v`
Expected:
  - Exit code: 0
  - Output contains: `--- PASS:` for each of the 5 tests

- [ ] **Step 3: 全量回归测试 — 确认 37 个旧测试 + 9 个新测试全过**
Run: `go test ./pkg/... ./cmd/... 2>&1 | tail -6`
Expected:
  - Exit code: 0
  - 5 个包全部 `ok`,无 FAIL

- [ ] **Step 4: 检查覆盖率提升 — die/dief 错误分支被解锁**
Run: `go test -coverprofile=/tmp/cmd_cov2.out ./cmd/cvss-cli/ >/dev/null 2>&1 && go tool cover -func=/tmp/cmd_cov2.out | grep -E 'die|dief|^total'`
Expected:
  - Exit code: 0
  - `die` 行覆盖率 > 0%(从 0.0% 提升,因 TestBuildCommand/InvalidMetricValue 等命中 die 路径)
  - `dief` 行覆盖率 > 0%(从 0.0% 提升)
  - `total` 高于 92.7%

- [ ] **Step 5: 验证生产行为仍零变化 — 构建并实测错误输出**
Run: `go build -o /tmp/cvss ./cmd/cvss-cli/ && /tmp/cvss score "INVALID" 2>&1; echo "EXIT=$?"; /tmp/cvss preset "bogus" 2>&1; echo "EXIT=$?"`
Expected:
  - Exit code: 0(build 阶段)
  - score EXIT=1, output contains `Parse error`
  - preset EXIT=1, output contains `Unknown severity`

- [ ] **Step 6: 清理临时文件**
Run: `rm -f /tmp/cvss /tmp/cov_pkg.out /tmp/cov_cmd.out /tmp/cmd_cov2.out /tmp/cmd_cov.html; git status --short`
Expected:
  - Exit code: 0
  - 工作区干净(无未跟踪文件)

- [ ] **Step 7: 提交**
Run: `git add cmd/cvss-cli/cli_smoke_test.go && git commit -m "test(cli): cover preset/build/describe/get/severity error paths"`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header 含 Goal+Architecture+Tech Stack? | PASS | 三者齐备,Architecture 回答了数据流(stdout/stderr pipe→recover)、关键组件(exitFunc/runCommandExpectError)、设计理由(注入 panic 而非重构 30 个文件为 RunE) |
| 2 | 每个 Task 标注 Depends on? | PASS | T1 None,T2 依赖 T1,T3 依赖 T2 |
| 3 | 每个 Task 列出精确文件路径? | PASS | 均为 cmd/cvss-cli/helpers.go 或 cli_smoke_test.go,标注行号与插入位置 |
| 4 | 每个 Task 有 3-8 Step? | PASS | T1=4,T2=4,T3=7 |
| 5 | 新文件步骤含完整代码? | PASS | exitFunc 声明 + runCommandExpectError 完整函数(含 defer 还原、recover、双 pipe) |
| 6 | 修改步骤含完整函数? | PASS | die/dief 替换后完整函数给出;测试函数完整给出 |
| 7 | 代码块 5-80 行? | PASS | runCommandExpectError ~45 行,测试函数 6-12 行 |
| 8 | 无悬空引用? | PASS | exitFunc/resetFlags/rootCmd/runCommand/bytes/io/os/strings 均已在现有文件定义或 import |
| 9 | 每个 Task 有验证命令? | PASS | 均有 Run+Expected(含 EXIT 与 output pattern) |
| 10 | Spec 需求有对应 Task? | PASS | 可测化(T1)+辅助函数与parse错误(T2)+业务错误路径(T3) |
| 11 | 每个 Task 可独立验证? | PASS | 每个有独立验证 Step(构建/测试/覆盖率) |
| 12 | 无 TBD/TODO? | PASS | 无 |
| 13 | 无抽象指令? | PASS | 每个 dief 分支有具体测试函数与断言关键词 |
| 14 | 跨 Task 一致性? | PASS | exitFunc/runCommandExpectError/resetFlags 在 T1-T3 签名一致 |
| 15 | 保存位置正确? | PASS | docs/superpowers/plans/2026-07-12-cli-error-path-testability.md |

**Status:** ✅ ALL PASS

## Execution Selection

**Tasks:** 3
**Dependencies:** yes (T1→T2→T3)
**User Preference:** none (zero-confirm mode)
**Decision:** Inline
**Reasoning:** 3 个 Task 都是同一目录 2 个文件的增量改动,顺序依赖(可测化先于测试),无需子代理并行;Inline 执行最快且能逐 Step 验证

⏹️ Phase 4 Complete: Execution selected, Inline execution
