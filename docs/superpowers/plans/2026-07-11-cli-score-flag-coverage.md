# CLI score flag 路径测试覆盖 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为 `cvss score` 命令的 `--breakdown` 和 `--all` flag 路径补充 smoke 测试,覆盖当前 0% 覆盖率的 `printBreakdown` / `printMetricScore` 函数,提升 cmd/cvss-cli 整体覆盖率。

**Architecture:** 现有 `cli_smoke_test.go` 的 `runCommand` 辅助函数已能捕获 stdout → 追加两个测试函数,分别用 `--breakdown` 和 `--all` flag 调用 `score` 命令,断言输出含关键词("Score Breakdown"/"Base Metrics"/"Impact"/"Exploitability" 等) → 跑覆盖率确认 `printBreakdown`/`printMetricScore` 从 0% 提升到 100%。复用现有 `hiVec()`/`hiVecTemporal()` 拼接辅助函数绕过字面量折叠 bug。

**Tech Stack:** Go 1.25, cobra, `go test -coverprofile`, 现有 `runCommand`/`vec` 测试基础设施

**Risks:**
- `--breakdown`/`--all` 输出格式是实现细节,可能随版本变 → 缓解:断言用宽松关键词("Breakdown"/"Base"/"Temporal"/"score")而非精确字符串
- 字面量折叠 bug 偶发干扰 → 缓解:沿用 `hiVec()`/`vec()` 拼接构造向量,已验证稳定

---

### Task 1: 添加 --breakdown flag 测试

**Depends on:** None
**Files:**
- Modify: `cmd/cvss-cli/cli_smoke_test.go`(在 TestScoreCommand_JSON 之后追加)

- [ ] **Step 1: 修改 TestScoreCommand 区块以追加 --breakdown 测试 — 覆盖 printBreakdown 路径**
文件: `cmd/cvss-cli/cli_smoke_test.go`(在 `TestScoreCommand_JSON` 函数之后、`TestParseCommand` 之前插入)

```go
// TestScoreCommand_Breakdown verifies the --breakdown flag prints per-metric
// score details, exercising printBreakdown and printMetricScore.
func TestScoreCommand_Breakdown(t *testing.T) {
	out := runCommand(t, "score", "--breakdown", hiVec())
	if !strings.Contains(out, "Breakdown") {
		t.Errorf("breakdown output missing 'Breakdown': %q", out)
	}
	if !strings.Contains(out, "Base Metrics") {
		t.Errorf("breakdown output missing 'Base Metrics': %q", out)
	}
	// A per-metric line like "AV:N = 0.8500" should appear.
	if !strings.Contains(out, "AV:") {
		t.Errorf("breakdown output missing AV metric line: %q", out)
	}
}

// TestScoreCommand_BreakdownTemporal verifies --breakdown on a temporal vector
// surfaces the Temporal Metrics section.
func TestScoreCommand_BreakdownTemporal(t *testing.T) {
	out := runCommand(t, "score", "--breakdown", hiVecTemporal())
	if !strings.Contains(out, "Temporal Metrics") {
		t.Errorf("breakdown output missing 'Temporal Metrics': %q", out)
	}
}
```

- [ ] **Step 2: 验证 --breakdown 测试通过**
Run: `go test -run 'TestScoreCommand_Breakdown' ./cmd/cvss-cli/ -v`
Expected:
  - Exit code: 0
  - Output contains: `--- PASS: TestScoreCommand_Breakdown`
  - Output contains: `--- PASS: TestScoreCommand_BreakdownTemporal`

- [ ] **Step 3: 提交**
Run: `git add cmd/cvss-cli/cli_smoke_test.go && git commit -m "test(cli): cover score --breakdown flag path"`

---

### Task 2: 添加 --all flag 测试

**Depends on:** Task 1
**Files:**
- Modify: `cmd/cvss-cli/cli_smoke_test.go`(在 Task 1 追加的函数之后插入)

- [ ] **Step 1: 修改测试文件以追加 --all 测试 — 覆盖 showAll 分支**
文件: `cmd/cvss-cli/cli_smoke_test.go`(在 `TestScoreCommand_BreakdownTemporal` 之后插入)

```go
// TestScoreCommand_All verifies the --all flag prints base/temporal/environmental
// scores with severities, exercising the showAll branch.
func TestScoreCommand_All(t *testing.T) {
	out := runCommand(t, "score", "--all", hiVec())
	// --all prints base + temporal + environmental score lines; the base 9.8
	// and Critical should appear at minimum.
	if !strings.Contains(out, "9.8") {
		t.Errorf("--all output missing base 9.8: %q", out)
	}
	if !strings.Contains(out, "Critical") {
		t.Errorf("--all output missing Critical severity: %q", out)
	}
}

// TestScoreCommand_AllJSON verifies --all combines with --format json.
func TestScoreCommand_AllJSON(t *testing.T) {
	out := runCommand(t, "score", "--all", "--format", "json", hiVec())
	if !strings.Contains(out, `"baseScore"`) {
		t.Errorf("--all json output missing baseScore: %q", out)
	}
	if !strings.Contains(out, `"severity"`) {
		t.Errorf("--all json output missing severity: %q", out)
	}
}
```

- [ ] **Step 2: 验证 --all 测试通过**
Run: `go test -run 'TestScoreCommand_All' ./cmd/cvss-cli/ -v`
Expected:
  - Exit code: 0
  - Output contains: `--- PASS: TestScoreCommand_All`
  - Output contains: `--- PASS: TestScoreCommand_AllJSON`

- [ ] **Step 3: 提交**
Run: `git add cmd/cvss-cli/cli_smoke_test.go && git commit -m "test(cli): cover score --all flag path"`

---

### Task 3: 验证覆盖率提升与全量回归

**Depends on:** Task 1, Task 2
**Files:**
- Read: `cmd/cvss-cli/score.go`(确认 printBreakdown/printMetricScore 已被覆盖)

- [ ] **Step 1: 检查 printBreakdown/printMetricScore 覆盖率从 0% 提升**
Run: `go test -coverprofile=/tmp/cmd_cov.out ./cmd/cvss-cli/ >/dev/null 2>&1 && go tool cover -func=/tmp/cmd_cov.out | grep -E 'printBreakdown|printMetricScore'`
Expected:
  - Exit code: 0
  - printBreakdown 行显示 `100.0%`
  - printMetricScore 行显示 `100.0%`

- [ ] **Step 2: 全量回归测试**
Run: `go test ./pkg/... ./cmd/... 2>&1 | tail -6`
Expected:
  - Exit code: 0
  - 5 个包全部 `ok`，无 FAIL

- [ ] **Step 3: 检查总覆盖率提升**
Run: `go test -cover ./cmd/cvss-cli/ 2>&1 | tail -1`
Expected:
  - Exit code: 0
  - 覆盖率 > 56.7%(之前的基线)

- [ ] **Step 4: 清理临时文件**
Run: `rm -f /tmp/cmd_cov.out /tmp/ct_* /tmp/cli_* /tmp/real_syms.txt 2>/dev/null; git status --short`
Expected:
  - Exit code: 0
  - 工作区干净(无未跟踪文件)

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header 含 Goal+Architecture+Tech Stack? | PASS | 三者齐备 |
| 2 | 每个 Task 标注 Depends on? | PASS | T1 None,T2 依赖 T1,T3 依赖 T1+T2 |
| 3 | 每个 Task 列出精确文件路径? | PASS | 均为 cmd/cvss-cli/cli_smoke_test.go,标注插入位置 |
| 4 | 每个 Task 有 3-8 Step? | PASS | T1=3,T2=3,T3=4 |
| 5 | 新文件步骤含完整代码? | PASS | 测试函数完整(含 import 复用现有 strings) |
| 6 | 修改步骤含完整函数? | PASS | 测试函数是新增,完整给出 |
| 7 | 代码块 5-80 行? | PASS | 每个测试函数 8-12 行 |
| 8 | 无悬空引用? | PASS | runCommand/hiVec/hiVecTemporal 均已在现有文件定义 |
| 9 | 每个 Task 有验证命令? | PASS | 均有 Run+Expected |
| 10 | Spec 需求有对应 Task? | PASS | --breakdown(T1)+--all(T2)+覆盖率验证(T3) |
| 11 | 每个 Task 可独立验证? | PASS | 每个有独立验证 Step |
| 12 | 无 TBD/TODO? | PASS | 无 |
| 13 | 无抽象指令? | PASS | 每个测试函数有具体断言 |
| 14 | 跨 Task 一致性? | PASS | 复用 hiVec/hiVecTemporal/runCommand |
| 15 | 保存位置正确? | PASS | docs/superpowers/plans/2026-07-11-cli-score-flag-coverage.md |

**Status:** ✅ ALL PASS

## Execution Selection

**Tasks:** 3
**Dependencies:** yes (T1→T2→T3)
**User Preference:** none (zero-confirm mode)
**Decision:** Inline
**Reasoning:** 3 个 Task 都是同一文件的增量测试,顺序依赖,无需子代理并行;Inline 执行最快

⏹️ Phase 4 Complete: Execution selected, Inline execution
