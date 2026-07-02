# Performance API Reference

This document provides detailed API reference for performance optimization features in CVSS Skills.

## Overview

The Performance API provides tools and utilities for:

- Benchmarking and profiling
- Memory optimization
- Concurrent processing
- Caching strategies
- Resource pooling

## Interfaces

### Benchmarker

```go
type Benchmarker interface {
    BenchmarkParsing(vectors []string, iterations int) *BenchmarkResult
    BenchmarkCalculation(vectors []*Cvss3x, iterations int) *BenchmarkResult
    BenchmarkEndToEnd(vectors []string, iterations int) *BenchmarkResult
    ProfileMemory(fn func()) *MemoryProfile
    ProfileCPU(fn func(), duration time.Duration) *CPUProfile
}
```

### ObjectPool

```go
type ObjectPool interface {
    Get() interface{}
    Put(obj interface{})
    Size() int
    Reset()
}

type ParserPool interface {
    ObjectPool
    GetParser() *parser.Cvss3xParser
    PutParser(p *parser.Cvss3xParser)
}

type CalculatorPool interface {
    ObjectPool
    GetCalculator() *cvss.Calculator
    PutCalculator(c *cvss.Calculator)
}
```

### Cache

```go
type Cache interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, ttl time.Duration)
    Delete(key string)
    Clear()
    Size() int
    Stats() *CacheStats
}

type LRUCache interface {
    Cache
    SetCapacity(capacity int)
    GetCapacity() int
}
```

## Core Types

### BenchmarkResult

```go
type BenchmarkResult struct {
    Name           string        `json:"name"`
    Iterations     int           `json:"iterations"`
    TotalDuration  time.Duration `json:"total_duration"`
    AverageDuration time.Duration `json:"average_duration"`
    MinDuration    time.Duration `json:"min_duration"`
    MaxDuration    time.Duration `json:"max_duration"`
    OperationsPerSecond float64  `json:"operations_per_second"`
    AllocationsPerOp   int64     `json:"allocations_per_op"`
    BytesPerOp         int64     `json:"bytes_per_op"`
}
```

### MemoryProfile

```go
type MemoryProfile struct {
    HeapAlloc      uint64 `json:"heap_alloc"`
    HeapSys        uint64 `json:"heap_sys"`
    HeapIdle       uint64 `json:"heap_idle"`
    HeapInuse      uint64 `json:"heap_inuse"`
    HeapReleased   uint64 `json:"heap_released"`
    HeapObjects    uint64 `json:"heap_objects"`
    StackInuse     uint64 `json:"stack_inuse"`
    StackSys       uint64 `json:"stack_sys"`
    MSpanInuse     uint64 `json:"mspan_inuse"`
    MSpanSys       uint64 `json:"mspan_sys"`
    MCacheInuse    uint64 `json:"mcache_inuse"`
    MCacheSys      uint64 `json:"mcache_sys"`
    GCSys          uint64 `json:"gc_sys"`
    OtherSys       uint64 `json:"other_sys"`
    NextGC         uint64 `json:"next_gc"`
    LastGC         uint64 `json:"last_gc"`
    PauseTotalNs   uint64 `json:"pause_total_ns"`
    PauseNs        []uint64 `json:"pause_ns"`
    NumGC          uint32 `json:"num_gc"`
    NumForcedGC    uint32 `json:"num_forced_gc"`
    GCCPUFraction  float64 `json:"gc_cpu_fraction"`
}
```

### CacheStats

```go
type CacheStats struct {
    Hits        int64   `json:"hits"`
    Misses      int64   `json:"misses"`
    HitRate     float64 `json:"hit_rate"`
    Size        int     `json:"size"`
    Capacity    int     `json:"capacity"`
    Evictions   int64   `json:"evictions"`
    LastAccess  time.Time `json:"last_access"`
}
```

## Factory Functions

### NewBenchmarker

```go
func NewBenchmarker() Benchmarker
```

Creates a new benchmarker instance for performance testing.

**Returns:**
- `Benchmarker`: New benchmarker instance

### NewParserPool

```go
func NewParserPool(size int) ParserPool
```

Creates a new parser object pool with the specified size.

**Parameters:**
- `size`: Maximum number of parsers in the pool

**Returns:**
- `ParserPool`: New parser pool instance

### NewCalculatorPool

```go
func NewCalculatorPool(size int) CalculatorPool
```

Creates a new calculator object pool with the specified size.

**Parameters:**
- `size`: Maximum number of calculators in the pool

**Returns:**
- `CalculatorPool`: New calculator pool instance

### NewLRUCache

```go
func NewLRUCache(capacity int) LRUCache
```

Creates a new LRU cache with the specified capacity.

**Parameters:**
- `capacity`: Maximum number of items in the cache

**Returns:**
- `LRUCache`: New LRU cache instance

## Benchmarking Methods

### BenchmarkParsing

```go
func (b *Benchmarker) BenchmarkParsing(vectors []string, iterations int) *BenchmarkResult
```

Benchmarks vector parsing performance.

**Parameters:**
- `vectors`: CVSS vectors to parse
- `iterations`: Number of iterations to run

**Returns:**
- `*BenchmarkResult`: Benchmark results

### BenchmarkCalculation

```go
func (b *Benchmarker) BenchmarkCalculation(vectors []*Cvss3x, iterations int) *BenchmarkResult
```

Benchmarks score calculation performance.

**Parameters:**
- `vectors`: Parsed CVSS vectors
- `iterations`: Number of iterations to run

**Returns:**
- `*BenchmarkResult`: Benchmark results

### BenchmarkEndToEnd

```go
func (b *Benchmarker) BenchmarkEndToEnd(vectors []string, iterations int) *BenchmarkResult
```

Benchmarks end-to-end processing performance.

**Parameters:**
- `vectors`: CVSS vectors to process
- `iterations`: Number of iterations to run

**Returns:**
- `*BenchmarkResult`: Benchmark results

## Profiling Methods

### ProfileMemory

```go
func (b *Benchmarker) ProfileMemory(fn func()) *MemoryProfile
```

Profiles memory usage of a function.

**Parameters:**
- `fn`: Function to profile

**Returns:**
- `*MemoryProfile`: Memory usage profile

### ProfileCPU

```go
func (b *Benchmarker) ProfileCPU(fn func(), duration time.Duration) *CPUProfile
```

Profiles CPU usage of a function.

**Parameters:**
- `fn`: Function to profile
- `duration`: Profiling duration

**Returns:**
- `*CPUProfile`: CPU usage profile

## Object Pool Methods

### Get

```go
func (p *ParserPool) Get() interface{}
func (p *ParserPool) GetParser() *parser.Cvss3xParser
```

Gets an object from the pool.

**Returns:**
- Object from the pool or new object if pool is empty

### Put

```go
func (p *ParserPool) Put(obj interface{})
func (p *ParserPool) PutParser(parser *parser.Cvss3xParser)
```

Returns an object to the pool.

**Parameters:**
- `obj`: Object to return to the pool

### Size

```go
func (p *ObjectPool) Size() int
```

Returns the current size of the pool.

**Returns:**
- `int`: Number of objects in the pool

### Reset

```go
func (p *ObjectPool) Reset()
```

Clears all objects from the pool.

## Cache Methods

### Get

```go
func (c *Cache) Get(key string) (interface{}, bool)
```

Retrieves a value from the cache.

**Parameters:**
- `key`: Cache key

**Returns:**
- `interface{}`: Cached value
- `bool`: True if key exists

### Set

```go
func (c *Cache) Set(key string, value interface{}, ttl time.Duration)
```

Stores a value in the cache.

**Parameters:**
- `key`: Cache key
- `value`: Value to cache
- `ttl`: Time to live

### Delete

```go
func (c *Cache) Delete(key string)
```

Removes a value from the cache.

**Parameters:**
- `key`: Cache key to remove

### Stats

```go
func (c *Cache) Stats() *CacheStats
```

Returns cache statistics.

**Returns:**
- `*CacheStats`: Cache statistics

## Performance Utilities

### ProcessorOptimizer

```go
type ProcessorOptimizer struct {
    ParserPool     ParserPool
    CalculatorPool CalculatorPool
    Cache          Cache
    Metrics        *PerformanceMetrics
}

func NewProcessorOptimizer(config *OptimizerConfig) *ProcessorOptimizer
```

Creates an optimized processor with pooling and caching.

### ConcurrentProcessor

```go
type ConcurrentProcessor struct {
    WorkerCount int
    BufferSize  int
    Timeout     time.Duration
}

func (cp *ConcurrentProcessor) ProcessVectors(vectors []string) ([]Result, error)
```

Processes vectors concurrently using worker pools.

### BatchProcessor

```go
type BatchProcessor struct {
    BatchSize   int
    MaxBatches  int
    Parallelism int
}

func (bp *BatchProcessor) ProcessBatches(vectors []string) ([]Result, error)
```

Processes vectors in batches for memory efficiency.

## Performance Metrics

### PerformanceMetrics

```go
type PerformanceMetrics struct {
    ProcessedVectors    int64
    TotalDuration      time.Duration
    AverageDuration    time.Duration
    ErrorCount         int64
    CacheHitRate       float64
    MemoryUsage        uint64
    GoroutineCount     int
}

func (pm *PerformanceMetrics) Record(duration time.Duration, err error)
func (pm *PerformanceMetrics) GetStats() *PerformanceStats
func (pm *PerformanceMetrics) Reset()
```

Tracks performance metrics during processing.

## Configuration

### OptimizerConfig

```go
type OptimizerConfig struct {
    ParserPoolSize     int           `json:"parser_pool_size"`
    CalculatorPoolSize int           `json:"calculator_pool_size"`
    CacheCapacity      int           `json:"cache_capacity"`
    CacheTTL           time.Duration `json:"cache_ttl"`
    EnableMetrics      bool          `json:"enable_metrics"`
    WorkerCount        int           `json:"worker_count"`
    BufferSize         int           `json:"buffer_size"`
    BatchSize          int           `json:"batch_size"`
}
```

Configuration for performance optimization.

## Best Practices

### Memory Management

1. **Use Object Pools**: Reuse parser and calculator instances
2. **Limit Cache Size**: Set appropriate cache capacity
3. **Monitor Memory**: Track memory usage and GC pressure
4. **Batch Processing**: Process large datasets in chunks

### Concurrency

1. **Worker Pools**: Use fixed number of workers
2. **Buffered Channels**: Prevent goroutine blocking
3. **Timeout Handling**: Set appropriate timeouts
4. **Error Handling**: Handle errors gracefully in concurrent code

### Caching

1. **Cache Strategy**: Choose appropriate cache eviction policy
2. **TTL Settings**: Set reasonable time-to-live values
3. **Cache Warming**: Pre-populate cache with common values
4. **Monitor Hit Rate**: Track cache effectiveness

## Examples

### Basic Benchmarking

```go
benchmarker := NewBenchmarker()
vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
}

result := benchmarker.BenchmarkParsing(vectors, 1000)
fmt.Printf("Average duration: %v\n", result.AverageDuration)
fmt.Printf("Operations/sec: %.0f\n", result.OperationsPerSecond)
```

### Object Pool Usage

```go
pool := NewParserPool(10)
defer pool.Reset()

parser := pool.GetParser()
defer pool.PutParser(parser)

vector, err := parser.Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

### Cache Usage

```go
cache := NewLRUCache(1000)

// Store result
cache.Set("vector1", result, 1*time.Hour)

// Retrieve result
if cached, found := cache.Get("vector1"); found {
    result := cached.(*Result)
    // Use cached result
}
```

## Related Documentation

- [Performance Examples](/examples/performance) - Practical performance optimization
- [Concurrent Processing](/api/performance) - Advanced concurrency patterns
- [Memory Management](/api/performance) - Memory optimization techniques
