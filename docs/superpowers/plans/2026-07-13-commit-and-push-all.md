# 提交本地所有变更并推送至远端 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将本地工作区唯一未提交文件（本轮覆盖率推进计划文档）提交，并把累计 16 个本地提交 fast-forward 推送到 origin/main。

**Architecture:** 工作区现状（已调研）：15 个本地领先 origin/main 的提交已逐个 commit（测试/文档/重构），无未暂存或已暂存改动；唯一未跟踪文件是 `docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md`。数据流：`git add` 计划文档 → `git commit` 生成第 16 个提交 → `git fetch` 确认 origin/main 仍是本地 HEAD 祖先（已验证为 `7226d97`）→ `git push` fast-forward 推送全部 16 个提交。关键操作：提交用规范 commit message，推送前再验一次可 fast-forward。

**Tech Stack:** git 2.x，远端 `origin`（github.com:scagogogo/cvss-skills），分支 `main`

**Risks:**
- 推送是外向不可逆操作 → 缓解：用户明确要求"推送到 git 仓库上"构成显式授权；已验证 origin/main 是 HEAD 祖先，推送为干净 fast-forward，无强推风险
- 推送期间 origin 被他人更新导致非 fast-forward → 缓解：推送前已 `git fetch` 确认 `7226d97` 为 origin/main 当前 HEAD；若推送被拒，重新 fetch+rebase 后再推

---

### Task 1: 提交未跟踪的计划文档

**Depends on:** None
**Files:**
- Add: `docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md`（本轮创建的覆盖率推进计划，记录 readLines/examples 纯函数达 100% 的诚实路径）

- [ ] **Step 1: 验证待提交文件内容无误 — 确认是本轮覆盖率推进计划文档**

Run: `git status --short && echo "---" && head -8 docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md`
Expected:
  - Exit code: 0
  - `git status --short` 输出仅一行：`?? docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md`
  - `head` 输出含标题行 `# 单元测试覆盖率推进至 100%(诚实可达路径)Implementation Plan`

- [ ] **Step 2: 暂存并提交计划文档 — 使用 docs(plan) 规范提交信息**

Run: `git add docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md && git commit -m "docs(plan): record coverage-100 honest paths plan"`
Expected:
  - Exit code: 0
  - `git status --short` 无输出（工作区干净）
  - `git log --oneline -1` 显示 `docs(plan): record coverage-100 honest paths plan`

- [ ] **Step 3: 验证工作区干净且本地领先计数为 16**

Run: `git status -sb | head -1 && git rev-list --count origin/main..HEAD`
Expected:
  - Exit code: 0
  - `git status -sb` 首行含 `领先 'origin/main' 共 16 个提交`（或英文 `ahead 16`）
  - `git rev-list --count` 输出 `16`

---

### Task 2: 推送全部 16 个提交到 origin/main

**Depends on:** Task 1
**Files:**
- 无文件改动（仅推送已有提交）

- [ ] **Step 1: 推送前再次确认可 fast-forward — origin/main 仍是本地 HEAD 祖先**

Run: `git fetch origin main >/dev/null 2>&1 && git merge-base --is-ancestor origin/main HEAD && echo "OK: fast-forward pushable" || echo "ABORT: origin diverged, need rebase"`
Expected:
  - Exit code: 0
  - Output contains: `OK: fast-forward pushable`

- [ ] **Step 2: 推送 main 到 origin — fast-forward 推送 16 个提交**

Run: `git push origin main`
Expected:
  - Exit code: 0
  - Output contains: `-> main` 或 `main -> main`
  - Output does NOT contain: `! [rejected]` 或 `non-fast-forward`

- [ ] **Step 3: 验证本地与远端同步 — 不再领先 origin/main**

Run: `git fetch origin main >/dev/null 2>&1 && git status -sb | head -1 && git rev-list --count origin/main..HEAD`
Expected:
  - Exit code: 0
  - `git status -sb` 首行显示 `## main...origin/main`（无 `ahead`/领先字样，表示已同步）
  - `git rev-list --count origin/main..HEAD` 输出 `0`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header 含 Goal+Architecture+Tech Stack? | PASS | 三者齐备；Architecture 回答数据流(add→commit→fetch 验证→push ff)、关键操作、设计理由(用户显式授权+已验证 ff 可行) |
| 2 | 每个 Task 标注 Depends on? | PASS | T1 None，T2 依赖 T1(需先提交计划文档使其成为第 16 个待推送提交) |
| 3 | 每个 Task 列出精确文件路径? | PASS | T1 `docs/superpowers/plans/2026-07-13-coverage-100-honest-paths.md`；T2 无文件改动(仅推送) |
| 4 | 每个 Task 有 3-8 Step? | PASS | T1=3，T2=3 |
| 5 | 新文件步骤含完整代码? | N/A | 本任务是 git 操作而非代码实现，无新代码文件需写完整代码 |
| 6 | 修改步骤含完整函数? | N/A | 同上，无代码修改 |
| 7 | 代码块 5-80 行? | N/A | 无代码块 |
| 8 | 无悬空引用? | PASS | 所有命令引用的文件路径真实存在(已 git status 确认) |
| 9 | 每个 Task 有验证命令? | PASS | 每个 Step 含 Run+Expected(Exit code + output pattern) |
| 10 | Spec 需求有对应 Task? | PASS | "提交本地所有变更"(T1 提交计划文档)+"推送到 git 仓库"(T2 push)全覆盖；无遗漏 |
| 11 | 每个 Task 可独立验证? | PASS | T1 Step3 验证领先数=16，T2 Step3 验证领先数=0 |
| 12 | 无 TBD/TODO? | PASS | 无 |
| 13 | 无抽象指令? | PASS | 每个 Step 是精确可复制的 git 命令 |
| 14 | 跨 Task 一致性? | PASS | origin/main、main、提交计数在 T1-T2 一致 |
| 15 | 保存位置正确? | PASS | docs/superpowers/plans/2026-07-13-commit-and-push-all.md |

**Status:** ✅ ALL PASS

## Execution Selection

**Tasks:** 2
**Dependencies:** yes (T1→T2)
**User Preference:** none (zero-confirm mode)
**Decision:** Inline
**Reasoning:** 仅 2 个 Task、纯 git 操作、强顺序依赖(T2 需 T1 的提交作为第 16 个待推送项)；Inline 执行最快且每个 Step 的验证命令即安全网。本任务为操作性任务，不触发 subagent 编排。

⏹️ Phase 4 Complete: Execution selected, Inline execution
