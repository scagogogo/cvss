---
title: 把 CVSS 向量存入数据库并按分排序
description: 用 cvss.Scan/Value（sql.Scanner/driver.Valuer）把 CVSS 向量持久化到 SQL，再用 NewCvss3xSlice 按分排序返回。
---

# 🗄️ 把 CVSS 向量存入数据库并按分排序

## 问题

你想把 CVSS 向量和 CVE 编号一起存进 SQL 数据库，读回时拿到强类型的 `Cvss3x` 对象，并按严重性返回——但又不想存一个要去同步维护的 `score` 冗余列。

## 方案

流程如下：

```mermaid
flowchart LR
  CV[🔤 Cvss3x object] --> V[✍️ Value → canonical string]
  V --> INS[💾 SQL INSERT<br/>store vector only]
  INS --> DB[(🗄️ vulns table<br/>id + cvss TEXT)]
  DB --> SEL[📖 SELECT cvss FROM vulns]
  SEL --> SC[📥 Scan → Cvss3x<br/>string / []byte / NULL]
  SC --> SL[Cvss3xSlice]
  SL --> SO[🔢 NewCvss3xSlice.Sort<br/>cache scores, no score column]
  SO --> OUT[✅ ordered by severity]
  classDef in fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef step fill:#e6f4ff,stroke:#1677ff,color:#003a8c
  classDef out fill:#f6ffed,stroke:#52c41a,color:#135200
  classDef data fill:#f9f0ff,stroke:#722ed1,color:#391085
  class CV in
  class V,INS,SEL,SC,SL,SO step
  class DB data
  class OUT out
```

### 1. 表结构

把向量串存在 `VARCHAR`/`TEXT` 列。一个由生成列/触发器维护的 `score` 列是可选的——讨论里会说为什么通常不需要。

```sql
CREATE TABLE vulns (
    id    VARCHAR(32)  PRIMARY KEY,
    cvss  TEXT         NOT NULL
);
```

### 2. 写入：`Value`（driver.Valuer）

`Cvss3x.Value()` 返回规范向量串，所以你可以直接把 `*Cvss3x` 传给 `db.Exec`。`(*Cvss3x)(nil).Value()` 写入 SQL `NULL`。

```go
import (
    "database/sql"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func insert(db *sql.DB, id string, v *cvss.Cvss3x) error {
    _, err := db.Exec("INSERT INTO vulns (id, cvss) VALUES (?, ?)", id, v)
    return err
}

// 用法：
//   insert(db, "CVE-2024-0001", cvss.CriticalV31())
//   insert(db, "CVE-2024-0002", cvss.LowV31())
```

### 3. 读取：`Scan`（sql.Scanner）

`Cvss3x.Scan` 接受 `string`、`[]byte` 或 `nil`（NULL → 空的 `Cvss3x`）。Scan 到 `cvss.Cvss3x`（不要 Scan 到指针），保证行值总是被实例化：

```go
func listAll(db *sql.DB) ([]*cvss.Cvss3x, error) {
    rows, err := db.Query("SELECT cvss FROM vulns")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []*cvss.Cvss3x
    for rows.Next() {
        var cv cvss.Cvss3x
        if err := rows.Scan(&cv); err != nil {
            return nil, err
        }
        out = append(out, &cv)
    }
    return out, rows.Err()
}
```

### 4. 用 `Cvss3xSlice` 按分排序

拿到切片后在内存里排序——`NewCvss3xSlice` 给每个向量算一次分并缓存：

```go
import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func printBySeverity(db *sql.DB) error {
    vectors, err := listAll(db)
    if err != nil {
        return err
    }

    // 降序——Critical 在前（默认）。
    slice := cvss.NewCvss3xSlice(vectors...).Sort()
    for i, cv := range slice.Items() {
        fmt.Printf("#%d %.1f %s\n", i+1, slice.ScoreAt(i), cv.String())
    }
    return nil
}
```

对一组给定输入，输出形如：

```text
#1 10.0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
#2 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
#3 3.7 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
```

## 讨论

::: tip 不要存 `score` 列
`score` 列会让向量去规范化——每次改指标都要重算分，过期的分是静默 bug。把向量串当唯一真相存起来，读的时候用 `NewCvss3xSlice` 算分。表很大时，分页算、每页算。
:::

- **NULL ↔ 空的 `Cvss3x`。** `Scan(nil)` 产生 `Cvss3x{Cvss3xBase: &Cvss3xBase{}}`（不是 nil 指针），nil 的 `*Cvss3x` 写入 SQL `NULL`。Scan 目标用 `*Cvss3x`（不要 `**Cvss3x`）。
- **非法串会让 scan 失败。** `Scan` 把解析错误包成 `"failed to scan Cvss3x: %w"`，所以坏行会在 `rows.Scan` 时暴露。如果列里可能有历史脏数据，先 Scan 到 `sql.NullString`，再防御性解析。
- **SQL 里的 `ORDER BY` 没法按分排序。** 分数不是一列，而且标准 SQL 算不了 CVSS。要么在 Go 里用 `Cvss3xSlice` 排（推荐），要么用应用代码维护一个 `score REAL` 列（仅当需要服务端按分分页时）。
- **无效向量被排到 −1。** `NewCvss3xSlice` 对 `Calculate` 失败的项记 `-1`；降序时它们排到最前，用 `if slice.ScoreAt(i) < 0 { continue }` 跳过。
- **PostgreSQL 的 `?` 占位符。** 示例用的是 `?`（MySQL/SQLite）。PostgreSQL 用 `$1`、`$2`；SQL Server 用 `@p1`。`Scan`/`Value` 接口与驱动无关。

## 另见

- [SQL 与排序](/zh/sdk/sql-sort)——`Scan`/`Value`/`Cvss3xSlice`/`Canonicalize` 参考
- [按严重性排序](/zh/recipes/sort-by-severity)——同样的排序，CLI + SDK，不入库
- [导出 JSON](/zh/recipes/export-to-json)——把存着的向量变成 API 的 JSON
- [生成测试数据](/zh/recipes/generate-test-data)——用随机向量填充 `vulns` 表
