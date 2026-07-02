# Performance Optimization

This guide covers advanced performance optimization techniques for CVSS Skills, including benchmarking, memory management, and concurrent processing strategies.

## Overview

Performance optimization is crucial for applications that process large volumes of CVSS vectors. This guide covers:

- Benchmarking and profiling
- Memory optimization
- Concurrent processing
- Caching strategies
- Batch processing
- Resource pooling

## Benchmarking

### Basic Benchmarks

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

### Memory Benchmarks

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

## Memory Optimization

### Object Pooling

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
    // Get parser from pool
    p := parserPool.Get().(*parser.Cvss3xParser)
    defer parserPool.Put(p)
    
    // Reset and use parser
    p.SetVector(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        return 0, err
    }
    
    // Get calculator from pool
    calc := calculatorPool.Get().(*cvss.Calculator)
    defer calculatorPool.Put(calc)
    
    // Reset and use calculator
    calc.SetVector(vector)
    return calc.Calculate()
}
```

### Memory-Efficient Batch Processing

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
        
        // Force GC after each batch to manage memory
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

## Concurrent Processing

### Worker Pool Pattern

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
    
    // Start workers
    for w := 0; w < numWorkers; w++ {
        go vectorWorker(jobs, results)
    }
    
    // Send jobs
    for i, vector := range vectors {
        jobs <- VectorJob{Vector: vector, Index: i}
    }
    close(jobs)
    
    // Collect results
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

### Pipeline Processing

```go
func ProcessVectorsPipeline(vectors []string) <-chan VectorResult {
    results := make(chan VectorResult)
    
    go func() {
        defer close(results)
        
        // Stage 1: Parse vectors
        parsed := parseVectorsPipeline(vectors)
        
        // Stage 2: Calculate scores
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

## Caching Strategies

### LRU Cache Implementation

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

// Cached vector processor
type CachedProcessor struct {
    cache *LRUCache
}

func NewCachedProcessor(cacheSize int) *CachedProcessor {
    return &CachedProcessor{
        cache: NewLRUCache(cacheSize),
    }
}

func (cp *CachedProcessor) ProcessVector(vectorStr string) (float64, error) {
    // Check cache first
    if score, found := cp.cache.Get(vectorStr); found {
        return score, nil
    }
    
    // Process vector
    score, err := ProcessVectorOptimized(vectorStr)
    if err != nil {
        return 0, err
    }
    
    // Cache result
    cp.cache.Put(vectorStr, score)
    return score, nil
}
```

## Profiling and Monitoring

### CPU Profiling

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

// Usage
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

### Memory Profiling

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

### Performance Metrics

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

## Best Practices

### 1. Choose the Right Approach

- **Single vectors**: Direct processing
- **Small batches (< 1000)**: Simple batch processing
- **Large batches (> 1000)**: Concurrent processing with worker pools
- **Streaming data**: Pipeline processing

### 2. Memory Management

- Use object pools for frequently created objects
- Process data in batches to control memory usage
- Force GC periodically for long-running processes
- Monitor memory usage with profiling

### 3. Caching Strategy

- Cache parsed vectors for repeated processing
- Use LRU cache to limit memory usage
- Consider cache invalidation strategies
- Monitor cache hit rates

### 4. Concurrent Processing

- Use worker pools for CPU-bound tasks
- Limit the number of goroutines to avoid overhead
- Use buffered channels to prevent blocking
- Handle errors gracefully in concurrent code

## Performance Testing

### Load Testing

```go
func TestHighLoad(t *testing.T) {
    vectors := generateTestVectors(100000)
    
    start := time.Now()
    results, err := ProcessVectorsConcurrent(vectors, runtime.NumCPU())
    duration := time.Since(start)
    
    require.NoError(t, err)
    require.Len(t, results, len(vectors))
    
    rate := float64(len(vectors)) / duration.Seconds()
    t.Logf("Processed %d vectors in %v (%.0f vectors/sec)", 
        len(vectors), duration, rate)
    
    // Assert minimum performance
    assert.Greater(t, rate, 1000.0, "Processing rate should be > 1000 vectors/sec")
}
```

### Stress Testing

```go
func TestMemoryStress(t *testing.T) {
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    // Process large number of vectors
    for i := 0; i < 10; i++ {
        vectors := generateTestVectors(10000)
        _, err := ProcessVectorsBatch(vectors, 1000)
        require.NoError(t, err)
    }
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    memIncrease := m2.Alloc - m1.Alloc
    t.Logf("Memory increase: %d KB", memIncrease/1024)
    
    // Assert memory usage is reasonable
    assert.Less(t, memIncrease, uint64(10*1024*1024), 
        "Memory increase should be < 10MB")
}
```

## Next Steps

After optimizing performance, you can explore:

- [Production Deployment](/examples/production) - Enterprise deployment patterns
- [Monitoring and Alerting](/examples/monitoring) - Production monitoring
- [Testing Guide](/api/testing) - Comprehensive testing strategies

## Related Documentation

- [Benchmarking Guide](/api/performance) - Detailed performance analysis
- [Memory Management](/api/performance) - Advanced memory optimization
- [Concurrent Programming](/api/performance) - Go concurrency patterns
