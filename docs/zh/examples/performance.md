# 性能优化

本指南涵盖 CVSS Skills 的高级性能优化技术，包括基准测试、内存管理和并发处理策略。

## 概述

性能优化对于处理大量 CVSS 向量的应用程序至关重要。本指南涵盖：

- 基准测试和性能分析
- 内存优化
- 并发处理
- 缓存策略
- 批量处理
- 资源池化

## 基准测试

### 基本基准测试

```go
package main

import (
    "testing"
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func BenchmarkVectorParsing(b *testing.B) {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        parser := parser.NewCvss3xParser(vectorStr)
        _, err := parser.Parse()
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkScoreCalculation(b *testing.B) {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parser := parser.NewCvss3xParser(vectorStr)
    vector, _ := parser.Parse()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        calculator := cvss.NewCalculator(vector)
        _, err := calculator.Calculate()
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkEndToEnd(b *testing.B) {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
        if err != nil {
            b.Fatal(err)
        }
        
        calculator := cvss.NewCalculator(vector)
        _, err = calculator.Calculate()
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

### 内存基准测试

```go
func BenchmarkMemoryAllocation(b *testing.B) {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    b.ReportAllocs()
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        parser := parser.NewCvss3xParser(vectorStr)
        vector, _ := parser.Parse()
        calculator := cvss.NewCalculator(vector)
        calculator.Calculate()
    }
}
```

## 内存优化

### 对象池化

```go
import "sync"

var parserPool = sync.Pool{
    New: func() interface{} {
        return parser.NewCvss3xParser("")
    },
}

var calculatorPool = sync.Pool{
    New: func() interface{} {
        return &cvss.Calculator{}
    },
}

func ProcessVectorOptimized(vectorStr string) (float64, error) {
    // 从池中获取解析器
    p := parserPool.Get().(*parser.Cvss3xParser)
    defer parserPool.Put(p)
    
    // 重置并使用解析器
    p.SetVector(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        return 0, err
    }
    
    // 从池中获取计算器
    calc := calculatorPool.Get().(*cvss.Calculator)
    defer calculatorPool.Put(calc)
    
    // 重置并使用计算器
    calc.SetVector(vector)
    return calc.Calculate()
}
```

### 内存高效的批量处理

```go
func ProcessVectorsBatch(vectors []string, batchSize int) ([]float64, error) {
    results := make([]float64, 0, len(vectors))
    
    for i := 0; i < len(vectors); i += batchSize {
        end := i + batchSize
        if end > len(vectors) {
            end = len(vectors)
        }
        
        batch := vectors[i:end]
        batchResults, err := processBatch(batch)
        if err != nil {
            return nil, err
        }
        
        results = append(results, batchResults...)
        
        // 每批处理后强制 GC 以管理内存
        if i%10000 == 0 {
            runtime.GC()
        }
    }
    
    return results, nil
}

func processBatch(vectors []string) ([]float64, error) {
    results := make([]float64, len(vectors))
    
    for i, vectorStr := range vectors {
        score, err := ProcessVectorOptimized(vectorStr)
        if err != nil {
            return nil, err
        }
        results[i] = score
    }
    
    return results, nil
}
```

## 并发处理

### 工作池模式

```go
type VectorJob struct {
    Vector string
    Index  int
}

type VectorResult struct {
    Score float64
    Index int
    Error error
}

func ProcessVectorsConcurrent(vectors []string, numWorkers int) ([]float64, error) {
    jobs := make(chan VectorJob, len(vectors))
    results := make(chan VectorResult, len(vectors))
    
    // 启动工作协程
    for w := 0; w < numWorkers; w++ {
        go vectorWorker(jobs, results)
    }
    
    // 发送任务
    for i, vector := range vectors {
        jobs <- VectorJob{Vector: vector, Index: i}
    }
    close(jobs)
    
    // 收集结果
    scores := make([]float64, len(vectors))
    for i := 0; i < len(vectors); i++ {
        result := <-results
        if result.Error != nil {
            return nil, result.Error
        }
        scores[result.Index] = result.Score
    }
    
    return scores, nil
}

func vectorWorker(jobs <-chan VectorJob, results chan<- VectorResult) {
    for job := range jobs {
        score, err := ProcessVectorOptimized(job.Vector)
        results <- VectorResult{
            Score: score,
            Index: job.Index,
            Error: err,
        }
    }
}
```

### 流水线处理

```go
func ProcessVectorsPipeline(vectors []string) <-chan VectorResult {
    results := make(chan VectorResult)
    
    go func() {
        defer close(results)
        
        // 阶段1：解析向量
        parsed := parseVectorsPipeline(vectors)
        
        // 阶段2：计算分数
        for vector := range parsed {
            if vector.Error != nil {
                results <- VectorResult{Error: vector.Error, Index: vector.Index}
                continue
            }
            
            calculator := cvss.NewCalculator(vector.Vector)
            score, err := calculator.Calculate()
            
            results <- VectorResult{
                Score: score,
                Index: vector.Index,
                Error: err,
            }
        }
    }()
    
    return results
}

type ParsedVector struct {
    Vector *cvss.Cvss3x
    Index  int
    Error  error
}

func parseVectorsPipeline(vectors []string) <-chan ParsedVector {
    parsed := make(chan ParsedVector)
    
    go func() {
        defer close(parsed)
        
        for i, vectorStr := range vectors {
            parser := parser.NewCvss3xParser(vectorStr)
            vector, err := parser.Parse()
            
            parsed <- ParsedVector{
                Vector: vector,
                Index:  i,
                Error:  err,
            }
        }
    }()
    
    return parsed
}
```

## 缓存策略

### LRU 缓存实现

```go
import "container/list"

type LRUCache struct {
    capacity int
    cache    map[string]*list.Element
    list     *list.List
    mutex    sync.RWMutex
}

type CacheEntry struct {
    key   string
    value float64
}

func NewLRUCache(capacity int) *LRUCache {
    return &LRUCache{
        capacity: capacity,
        cache:    make(map[string]*list.Element),
        list:     list.New(),
    }
}

func (c *LRUCache) Get(key string) (float64, bool) {
    c.mutex.RLock()
    defer c.mutex.RUnlock()
    
    if elem, exists := c.cache[key]; exists {
        c.list.MoveToFront(elem)
        return elem.Value.(*CacheEntry).value, true
    }
    return 0, false
}

func (c *LRUCache) Put(key string, value float64) {
    c.mutex.Lock()
    defer c.mutex.Unlock()
    
    if elem, exists := c.cache[key]; exists {
        c.list.MoveToFront(elem)
        elem.Value.(*CacheEntry).value = value
        return
    }
    
    if c.list.Len() >= c.capacity {
        oldest := c.list.Back()
        if oldest != nil {
            c.list.Remove(oldest)
            delete(c.cache, oldest.Value.(*CacheEntry).key)
        }
    }
    
    entry := &CacheEntry{key: key, value: value}
    elem := c.list.PushFront(entry)
    c.cache[key] = elem
}

// 缓存向量处理器
type CachedProcessor struct {
    cache *LRUCache
}

func NewCachedProcessor(cacheSize int) *CachedProcessor {
    return &CachedProcessor{
        cache: NewLRUCache(cacheSize),
    }
}

func (cp *CachedProcessor) ProcessVector(vectorStr string) (float64, error) {
    // 首先检查缓存
    if score, found := cp.cache.Get(vectorStr); found {
        return score, nil
    }
    
    // 处理向量
    score, err := ProcessVectorOptimized(vectorStr)
    if err != nil {
        return 0, err
    }
    
    // 缓存结果
    cp.cache.Put(vectorStr, score)
    return score, nil
}
```

## 性能分析和监控

### CPU 性能分析

```go
import (
    "os"
    "runtime/pprof"
)

func ProfileCPU(filename string, fn func()) error {
    f, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer f.Close()
    
    if err := pprof.StartCPUProfile(f); err != nil {
        return err
    }
    defer pprof.StopCPUProfile()
    
    fn()
    return nil
}

// 使用方法
func main() {
    vectors := generateTestVectors(100000)
    
    err := ProfileCPU("cpu.prof", func() {
        ProcessVectorsConcurrent(vectors, 8)
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

### 内存性能分析

```go
func ProfileMemory(filename string, fn func()) error {
    fn()
    
    f, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer f.Close()
    
    runtime.GC()
    return pprof.WriteHeapProfile(f)
}
```

### 性能指标

```go
type PerformanceMetrics struct {
    ProcessedVectors int64
    TotalDuration    time.Duration
    ErrorCount       int64
    CacheHits        int64
    CacheMisses      int64
    mutex           sync.RWMutex
}

func (pm *PerformanceMetrics) RecordProcessing(duration time.Duration, err error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    pm.ProcessedVectors++
    pm.TotalDuration += duration
    
    if err != nil {
        pm.ErrorCount++
    }
}

func (pm *PerformanceMetrics) RecordCacheHit() {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    pm.CacheHits++
}

func (pm *PerformanceMetrics) RecordCacheMiss() {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    pm.CacheMisses++
}

func (pm *PerformanceMetrics) GetStats() (float64, float64, float64) {
    pm.mutex.RLock()
    defer pm.mutex.RUnlock()
    
    avgDuration := float64(pm.TotalDuration) / float64(pm.ProcessedVectors)
    errorRate := float64(pm.ErrorCount) / float64(pm.ProcessedVectors)
    cacheHitRate := float64(pm.CacheHits) / float64(pm.CacheHits + pm.CacheMisses)
    
    return avgDuration, errorRate, cacheHitRate
}
```

## 最佳实践

### 1. 选择正确的方法

- **单个向量**: 直接处理
- **小批量 (< 1000)**: 简单批量处理
- **大批量 (> 1000)**: 使用工作池的并发处理
- **流式数据**: 流水线处理

### 2. 内存管理

- 对频繁创建的对象使用对象池
- 分批处理数据以控制内存使用
- 对长时间运行的进程定期强制 GC
- 使用性能分析监控内存使用

### 3. 缓存策略

- 缓存解析的向量以供重复处理
- 使用 LRU 缓存限制内存使用
- 考虑缓存失效策略
- 监控缓存命中率

### 4. 并发处理

- 对 CPU 密集型任务使用工作池
- 限制协程数量以避免开销
- 使用缓冲通道防止阻塞
- 在并发代码中优雅处理错误

## 性能测试

### 负载测试

```go
func TestHighLoad(t *testing.T) {
    vectors := generateTestVectors(100000)
    
    start := time.Now()
    results, err := ProcessVectorsConcurrent(vectors, runtime.NumCPU())
    duration := time.Since(start)
    
    require.NoError(t, err)
    require.Len(t, results, len(vectors))
    
    rate := float64(len(vectors)) / duration.Seconds()
    t.Logf("在 %v 内处理了 %d 个向量 (%.0f 向量/秒)", 
        duration, len(vectors), rate)
    
    // 断言最低性能
    assert.Greater(t, rate, 1000.0, "处理速率应该 > 1000 向量/秒")
}
```

### 压力测试

```go
func TestMemoryStress(t *testing.T) {
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    // 处理大量向量
    for i := 0; i < 10; i++ {
        vectors := generateTestVectors(10000)
        _, err := ProcessVectorsBatch(vectors, 1000)
        require.NoError(t, err)
    }
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    memIncrease := m2.Alloc - m1.Alloc
    t.Logf("内存增加: %d KB", memIncrease/1024)
    
    // 断言内存使用合理
    assert.Less(t, memIncrease, uint64(10*1024*1024), 
        "内存增加应该 < 10MB")
}
```

## 下一步

优化性能后，您可以探索：

- [生产部署](/zh/examples/edge-cases) - 企业部署模式
- [监控和告警](/zh/examples/monitoring) - 生产监控
- [测试指南](/zh/api/cvss/) - 全面的测试策略

## 相关文档

- [基准测试指南](/zh/examples/performance) - 详细的性能分析
- [内存管理](/zh/api/cvss/calculator) - 高级内存优化
- [并发编程](/zh/api/cvss/calculator) - Go 并发模式
