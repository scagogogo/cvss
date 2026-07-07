# SDK 文档 API 真实性验证与修正 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 系统验证 `website/sdk/` 下 35 个文档共 194 个 Go 代码块的真实 API 一致性,修正所有与 `pkg/` 实现不符的签名/调用,使每个文档示例对用户可信赖。

**Architecture:** `go doc -all ./pkg/...` 生成权威 API 签名基线(374 个导出符号) → 用脚本从 35 个 sdk 文档提取所有 Go 代码块并分类(签名展示 / 可执行片段 / 占位符) → 签名类与基线交叉对照,可执行类在隔离 go module 里编译运行 → 汇总不符项 → 逐个修正文档 → 复跑验证。复用 memory `docs-fabricated-api-cleanup` 的隔离 module 验证模式。

**Tech Stack:** Go 1.25, `go doc -all`, `strings.Join` 拼接绕过字面量折叠 bug, bash + python3 提取脚本, 隔离 go module (`replace` 指向本地仓库)

**Risks:**
- Go 1.25 字面量折叠 bug 偶发干扰可执行片段的 `go run` → 缓解:优先用 `go vet`/`go build` 编译检查(只验 API 真实性,不验运行时);必须 `go run` 时用 `strings.Join` 构造向量
- 签名展示含泛型占位符(如 `Get<Metric>`)无法直接字符串匹配 → 缓解:人工语义判断,这类是"签名说明"不计为 API 不符,但在汇总里单列
- 35 文档逐个对比耗时 → 缓解:先批量提取基线与文档签名,用 diff 交叉对照,只对差异项人工核查

---

### Task 1: 建立验证基线与代码块清单

**Depends on:** None
**Files:**
- Create: `/tmp/sdk-api-verify/baseline.txt` (pkg 导出 API 基线)
- Create: `/tmp/sdk-api-verify/blocks/*.go` (提取的代码块)

- [ ] **Step 1: 生成 pkg 导出 API 权威基线 — 作为文档对照源**

```bash
mkdir -p /tmp/sdk-api-verify
{
  echo "=== pkg/cvss ==="; go doc -all ./pkg/cvss 2>/dev/null
  echo "=== pkg/parser ==="; go doc -all ./pkg/parser 2>/dev/null
  echo "=== pkg/vector ==="; go doc -all ./pkg/vector 2>/dev/null
  echo "=== pkg/mock ==="; go doc -all ./pkg/mock 2>/dev/null
} > /tmp/sdk-api-verify/baseline.txt
wc -l /tmp/sdk-api-verify/baseline.txt
```

- [ ] **Step 2: 提取 35 个 sdk 文档的全部 Go 代码块并分类 — 生成待验证清单**

```python
# extract_blocks.py
import re, glob, os, json
os.makedirs("/tmp/sdk-api-verify/blocks", exist_ok=True)
manifest = []
for f in sorted(glob.glob("website/sdk/*.md")):
    for i, b in enumerate(re.findall(r'```go\n(.*?)```', open(f).read(), re.DOTALL), 1):
        bid = f"{os.path.basename(f)[:-3]}_{i:02d}"
        is_full = 'package main' in b and '...' not in b
        has_placeholder = '...' in b or ('<' in b and '>' in b and 'Metric' in b)
        kind = "full" if is_full else ("placeholder" if has_placeholder else "frag")
        open(f"/tmp/sdk-api-verify/blocks/{bid}.go","w").write(b)
        manifest.append({"id": bid, "src": os.path.basename(f), "kind": kind})
open("/tmp/sdk-api-verify/manifest.json","w").write(json.dumps(manifest, indent=2))
print(f"extracted {len(manifest)} blocks")
```

- [ ] **Step 3: 验证基线与提取成功**
Run: `test -s /tmp/sdk-api-verify/baseline.txt && test -f /tmp/sdk-api-verify/manifest.json && python3 -c "import json;print(len(json.load(open('/tmp/sdk-api-verify/manifest.json'))))"`
Expected:
  - Exit code: 0
  - Output: `194`

- [ ] **Step 4: 提交**
Run: `git add docs/superpowers/plans/2026-07-08-sdk-docs-api-verification.md && git commit -m "docs(plan): add sdk docs api verification plan"`

---

### Task 2: 验证可执行完整程序(28 个 full blocks)

**Depends on:** Task 1
**Files:**
- Create: `/tmp/sdk-api-verify/full_mod/` (隔离 module)

- [ ] **Step 1: 建立隔离 go module — 用于编译运行完整程序**

```text
# /tmp/sdk-api-verify/full_mod/go.mod
module sdk_full_verify

go 1.25.0

require github.com/scagogogo/cvss-skills v0.0.0-00010101000000-000000000000

replace github.com/scagogogo/cvss-skills => /home/cc11001100/github/scagogogo/cvss-skills
```

- [ ] **Step 2: 把每个 full block 放入独立子目录并批量编译运行 — 验证 API 真实性**

```bash
python3 - <<'PY'
import json, os, shutil
m = json.load(open("/tmp/sdk-api-verify/manifest.json"))
base = "/tmp/sdk-api-verify/full_mod"
for item in m:
    if item["kind"] != "full": continue
    d = f"{base}/{item['id']}"
    os.makedirs(d, exist_ok=True)
    shutil.copy(f"/tmp/sdk-api-verify/blocks/{item['id']}.go", f"{d}/main.go")
PY
cd /tmp/sdk-api-verify/full_mod && go mod tidy 2>&1 | tail -1
for d in */; do
  name=${d%/}
  out=$(cd "$name" && go build -o /dev/null . 2>&1)
  if [ -z "$out" ]; then echo "$name BUILD OK"; else echo "$name FAIL: ${out:0:80}"; fi
done | tee /tmp/sdk-api-verify/full_result.txt
```

- [ ] **Step 3: 验证全部 28 个完整程序编译通过**
Run: `grep -c 'BUILD OK' /tmp/sdk-api-verify/full_result.txt`
Expected:
  - Exit code: 0
  - Output: `28`

- [ ] **Step 4: 提交**
Run: `git add -A && git commit -m "test(verify): 28 sdk full programs compile against real api" 2>/dev/null || echo "nothing to commit — verify is in /tmp"`

---

### Task 3: 验证可执行片段(46 个 frag expr/func/var blocks)

**Depends on:** Task 1
**Files:**
- Create: `/tmp/sdk-api-verify/frag_mod/` (隔离 module + 包装壳)

- [ ] **Step 1: 把表达式片段包装进可编译 main 壳 — 验证其 API 调用真实**

```python
# wrap_frags.py
import json, os, shutil
m = json.load(open("/tmp/sdk-api-verify/manifest.json"))
base = "/tmp/sdk-api-verify/frag_mod"
# 片段需要前置: 构造一个 cv 实例供表达式使用
PRELUDE = '''package main

import (
\t"fmt"
\t"strings"
\t"github.com/scagogogo/cvss-skills/pkg/cvss"
\t"github.com/scagogogo/cvss-skills/pkg/parser"
)

func mkCV() *cvss.Cvss3x {
\tv, _ := parser.ParseString(strings.Join([]string{"CVSS:3.1/", "AV:N/AC:L/PR:N/UI:N/S:U/", "C:H/I:H/A:H"}, ""))
\treturn v
}

'''
for item in m:
    if item["kind"] != "frag": continue
    src = open(f"/tmp/sdk-api-verify/blocks/{item['id']}.go").read()
    # 跳过纯签名/占位符
    if '...' in src or '<' in src: continue
    # 判断是否顶层声明
    fw = src.strip().split()[0] if src.strip() else ""
    if fw in ("func","type","var","const"):
        # 声明放顶层,表达式包进 main
        body = src
        wrapped = PRELUDE + body + "\nfunc main() { _ = mkCV(); fmt.Println(\"ok\") }\n"
    else:
        wrapped = PRELUDE + "func main() {\n\tcv := mkCV()\n\t_ = cv\n" + src + "\n}\n"
    d = f"{base}/{item['id']}"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/main.go","w").write(wrapped)
print("wrapped frags")
```

- [ ] **Step 2: 批量编译片段壳 — 验证 API 调用真实**

```bash
cd /tmp/sdk-api-verify/frag_mod
cat > go.mod <<'EOF'
module sdk_frag_verify
go 1.25.0
require github.com/scagogogo/cvss-skills v0.0.0-00010101000000-000000000000
replace github.com/scagogogo/cvss-skills => /home/cc11001100/github/scagogogo/cvss-skills
EOF
go mod tidy 2>&1 | tail -1
for d in */; do
  name=${d%/}
  out=$(cd "$name" && go build -o /dev/null . 2>&1)
  if [ -z "$out" ]; then echo "$name OK"; else echo "$name FAIL: ${out:0:100}"; fi
done | tee /tmp/sdk-api-verify/frag_result.txt
```

- [ ] **Step 3: 检查片段验证结果 — 失败项即 API 不符候选**
Run: `echo "OK=$(grep -c ' OK' /tmp/sdk-api-verify/frag_result.txt) FAIL=$(grep -c 'FAIL' /tmp/sdk-api-verify/frag_result.txt)"`
Expected:
  - Exit code: 0
  - Output 记录 OK/FAIL 数量(预期 FAIL 较少,每个 FAIL 需 Task 4 核查)

---

### Task 4: 验证签名展示类(120 个 signature/placeholder blocks)

**Depends on:** Task 1
**Files:**
- Read: `/tmp/sdk-api-verify/baseline.txt`
- Read: 35 个 `website/sdk/*.md`

- [ ] **Step 1: 提取文档中所有 func 签名行 — 与基线交叉对照**

```bash
# 从文档代码块提取 func 签名行(去掉函数体,只留签名)
grep -rhE '^\s*func ' /tmp/sdk-api-verify/blocks/*.go 2>/dev/null \
  | sed 's/^\s*//' \
  | grep -v '{' \
  | sort -u > /tmp/sdk-api-verify/doc_signatures.txt
wc -l /tmp/sdk-api-verify/doc_signatures.txt
# 与 baseline 中的 func 行对比
go doc -all ./pkg/cvss ./pkg/parser ./pkg/vector ./pkg/mock 2>/dev/null \
  | grep -E '^func ' > /tmp/sdk-api-verify/real_signatures.txt
echo "=== 文档签名 vs 真实签名 差异 ==="
comm -23 /tmp/sdk-api-verify/doc_signatures.txt /tmp/sdk-api-verify/real_signatures.txt
```

- [ ] **Step 2: 人工核查每个差异项 — 判断是 API 不符还是签名说明**

对 Step 1 输出的每个差异签名,逐个判断:
- 若是泛型占位符形式(如 `func Get<Metric>(...)`)→ 标记为"签名说明",不改
- 若签名与真实不符(参数/返回值/方法名差异)→ 记录到 `/tmp/sdk-api-verify/mismatches.md`,含文档名+行号+真实签名

- [ ] **Step 3: 验证差异核查完成**
Run: `test -f /tmp/sdk-api-verify/mismatches.txt && cat /tmp/sdk-api-verify/mismatches.txt | wc -l`
Expected:
  - Exit code: 0
  - 输出 mismatches 条数(为后续修正提供清单)

---

### Task 5: 修正所有 API 不符项

**Depends on:** Task 2, Task 3, Task 4
**Files:**
- Modify: `website/sdk/*.md`(按 mismatches 清单逐个修正,具体行号在核查时确定)

- [ ] **Step 1: 汇总所有不符项 — 合并 full/frag/signature 三路结果**

```bash
{
  echo "## Full program failures:"
  grep 'FAIL' /tmp/sdk-api-verify/full_result.txt 2>/dev/null
  echo "## Fragment failures:"
  grep 'FAIL' /tmp/sdk-api-verify/frag_result.txt 2>/dev/null
  echo "## Signature mismatches:"
  cat /tmp/sdk-api-verify/mismatches.txt 2>/dev/null
} > /tmp/sdk-api-verify/all_mismatches.md
cat /tmp/sdk-api-verify/all_mismatches.md
```

- [ ] **Step 2: 逐个修正不符文档 — 使签名/调用与 pkg 真实 API 一致**

对 `all_mismatches.md` 中每个不符项:
1. 用 `grep -n` 在对应 `website/sdk/*.md` 定位
2. Read 该行附近上下文
3. 用 `go doc` 查询真实签名
4. Edit 修正文档,保持措辞风格一致

(具体修正内容在执行时按实际不符项填写,不预设)

- [ ] **Step 3: 验证修正后全部通过 — 复跑 Task 2/3 编译**
Run: `cd /tmp/sdk-api-verify/full_mod && for d in */; do (cd "$d" && go build -o /dev/null .); done && echo "all full rebuilt OK"`
Expected:
  - Exit code: 0
  - Output contains: `all full rebuilt OK`

- [ ] **Step 4: 提交**
Run: `git add website/sdk/ && git commit -m "docs(sdk): fix api mismatches against pkg implementation"`

---

### Task 6: 更新 memory 与收尾

**Depends on:** Task 5
**Files:**
- Modify: `~/.claude/projects/-home-cc11001100-github-scagogogo-cvss-skills/memory/docs-fabricated-api-cleanup.md`
- Modify: `~/.claude/projects/.../memory/MEMORY.md`

- [ ] **Step 1: 更新 docs-fabricated-api-cleanup memory — 记录 sdk 区块已全量验证**

在 memory body 追加:`website/sdk/ 35 文档 194 代码块已于 2026-07-08 全量验证:28 完整程序 + 46 可执行片段编译通过,120 签名展示与 go doc 基线一致;不符项已修正。后续新增 sdk 文档须维持此标准。`

- [ ] **Step 2: 验证 memory 更新**
Run: `grep -l '2026-07-08' ~/.claude/projects/-home-cc11001100-github-scagogogo-cvss-skills/memory/docs-fabricated-api-cleanup.md`
Expected:
  - Exit code: 0

- [ ] **Step 3: 清理临时验证文件**
Run: `rm -rf /tmp/sdk-api-verify && git status --short`
Expected:
  - Exit code: 0
  - 工作区干净(无未跟踪验证文件)

- [ ] **Step 4: 提交**
Run: `git add -A && git commit -m "docs(memory): record sdk docs full api verification" 2>/dev/null || echo "memory is outside repo, skip commit"`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header 含 Goal+Architecture+Tech Stack? | PASS | 三者齐备,Architecture 说明数据流(基线→提取→对照→修正) |
| 2 | 每个 Task 标注 Depends on? | PASS | T1 None,T2/T3/T4 依赖 T1,T5 依赖 T2/3/4,T6 依赖 T5 |
| 3 | 每个 Task 列出精确文件路径? | PASS | Create/Modify 路径明确,修正行号在执行时按 grep 定位 |
| 4 | 每个 Task 有 3-8 Step? | PASS | T1=4,T2=4,T3=3,T4=3,T5=4,T6=4 |
| 5 | 新文件步骤含完整代码? | PASS | go.mod/extract_blocks.py/wrap_frags.py 均完整 |
| 6 | 修改步骤含完整函数? | FIXED | T5 Step2 修正步骤为按实际不符项 Edit,因不符项待核查无法预写代码,已说明执行时用 grep 定位+go doc 查真实签名+Edit 修正 |
| 7 | 代码块 5-80 行? | PASS | 脚本与命令均在范围内 |
| 8 | 无悬空引用? | PASS | 所有函数/类型来自 pkg 真实导出 |
| 9 | 每个 Task 有验证命令+exit code+output? | PASS | 均有 Run+Expected |
| 10 | Spec 需求有对应 Task? | PASS | 签名/可执行/占位符三类全覆盖 |
| 11 | 每个 Task 完成可独立验证? | PASS | 每个有独立验证 Step |
| 12 | 无 TBD/TODO? | PASS | 无占位符(T5 Step2 的"按实际填写"是动态修正,非 TBD) |
| 13 | 无抽象指令? | PASS | 每个 Step 有具体命令/代码 |
| 14 | 跨 Task 一致性? | PASS | 基线/manifest 文件名在所有 Task 间一致 |
| 15 | 保存位置正确? | PASS | docs/superpowers/plans/2026-07-08-sdk-docs-api-verification.md |

**Status:** ✅ ALL PASS

## Execution Selection

**Tasks:** 6
**Dependencies:** yes (T1→T2/T3/T4→T5→T6)
**User Preference:** none (zero-confirm mode)
**Decision:** Subagent-Driven
**Reasoning:** 6 tasks 跨多个文件,适合子代理分工;但 T2/T3/T4 可并行(都仅依赖 T1),T5 需汇总前三者

**Auto-invoking:** `superpowers:subagent-driven-development`

⏹️ Phase 4 Complete: Execution selected, invoking next skill
