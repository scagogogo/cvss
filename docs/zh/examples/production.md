# 生产环境部署

本指南涵盖 CVSS Skills 的企业部署模式、配置管理和生产环境最佳实践。

## 概述

在生产环境中部署 CVSS Skills 需要仔细考虑以下方面：

- 可扩展性与性能
- 安全与合规
- 监控与可观测性
- 错误处理与恢复
- 配置管理
- 高可用

## 部署架构

### 微服务架构

```go
// CVSS 服务
type CVSSService struct {
    cache      cache.Cache
    metrics    metrics.Collector
    logger     logger.Logger
}

func NewCVSSService(config *Config) *CVSSService {
    return &CVSSService{
        cache:      cache.NewRedisCache(config.Redis),
        metrics:    metrics.NewPrometheus(),
        logger:     logger.NewStructured(config.LogLevel),
    }
}

func (s *CVSSService) ProcessVector(ctx context.Context, vectorStr string) (*VectorResult, error) {
    span, ctx := opentracing.StartSpanFromContext(ctx, "cvss.process_vector")
    defer span.Finish()

    // 先查缓存
    if result, found := s.cache.Get(ctx, vectorStr); found {
        s.metrics.IncrementCacheHits()
        return result, nil
    }

    // 解析并计算（parser/calculator 开销小，按调用绑定）
    start := time.Now()
    vector, err := parser.ParseString(vectorStr)
    if err != nil {
        s.metrics.IncrementErrors("parse_error")
        return nil, fmt.Errorf("failed to parse vector: %w", err)
    }

    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        s.metrics.IncrementErrors("calculation_error")
        return nil, fmt.Errorf("failed to calculate score: %w", err)
    }

    result := &VectorResult{
        Vector:   vectorStr,
        Score:    score,
        Severity: calculator.GetSeverityRating(score),
    }
    
    // 缓存结果
    s.cache.Set(ctx, vectorStr, result, time.Hour)
    s.metrics.RecordProcessingTime(time.Since(start))
    s.metrics.IncrementProcessed()
    
    return result, nil
}
```

### HTTP API 服务器

```go
func main() {
    config := loadConfig()
    service := NewCVSSService(config)
    
    router := gin.New()
    router.Use(gin.Recovery())
    router.Use(middleware.RequestID())
    router.Use(middleware.Logging())
    router.Use(middleware.Metrics())
    router.Use(middleware.RateLimit(config.RateLimit))
    
    v1 := router.Group("/api/v1")
    {
        v1.POST("/vectors/analyze", handleVectorAnalysis(service))
        v1.POST("/vectors/batch", handleBatchAnalysis(service))
        v1.GET("/vectors/:id", handleGetVector(service))
        v1.GET("/health", handleHealth(service))
        v1.GET("/metrics", gin.WrapH(promhttp.Handler()))
    }
    
    server := &http.Server{
        Addr:         config.Address,
        Handler:      router,
        ReadTimeout:  config.ReadTimeout,
        WriteTimeout: config.WriteTimeout,
        IdleTimeout:  config.IdleTimeout,
    }
    
    // 优雅关闭
    go func() {
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()
    
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := server.Shutdown(ctx); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }
}
```

### 容器部署

```dockerfile
# 多阶段构建
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cvss-service ./cmd/server

# 最终阶段
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/cvss-service .
COPY --from=builder /app/configs/production.yaml ./config.yaml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./cvss-service", "--config", "config.yaml"]
```

## 配置管理

### 基于环境的配置

```go
type Config struct {
    Server   ServerConfig   `yaml:"server"`
    Database DatabaseConfig `yaml:"database"`
    Redis    RedisConfig    `yaml:"redis"`
    Logging  LoggingConfig  `yaml:"logging"`
    Metrics  MetricsConfig  `yaml:"metrics"`
}

type ServerConfig struct {
    Address      string        `yaml:"address" env:"SERVER_ADDRESS" default:":8080"`
    ReadTimeout  time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT" default:"30s"`
    WriteTimeout time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT" default:"30s"`
    IdleTimeout  time.Duration `yaml:"idle_timeout" env:"SERVER_IDLE_TIMEOUT" default:"60s"`
}

func LoadConfig() (*Config, error) {
    config := &Config{}
    
    // 从文件加载
    if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
        data, err := os.ReadFile(configFile)
        if err != nil {
            return nil, err
        }
        
        if err := yaml.Unmarshal(data, config); err != nil {
            return nil, err
        }
    }
    
    // 用环境变量覆盖
    if err := env.Parse(config); err != nil {
        return nil, err
    }
    
    return config, nil
}
```

### Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cvss-service
  labels:
    app: cvss-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cvss-service
  template:
    metadata:
      labels:
        app: cvss-service
    spec:
      containers:
      - name: cvss-service
        image: cvss-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: SERVER_ADDRESS
          value: ":8080"
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: cvss-secrets
              key: redis-url
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: cvss-service
spec:
  selector:
    app: cvss-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

## 高可用

### 负载均衡

```yaml
# HAProxy 配置
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend cvss_frontend
    bind *:80
    default_backend cvss_backend

backend cvss_backend
    balance roundrobin
    option httpchk GET /health
    server cvss1 cvss-service-1:8080 check
    server cvss2 cvss-service-2:8080 check
    server cvss3 cvss-service-3:8080 check
```

### 熔断器模式

```go
type CircuitBreaker struct {
    maxFailures int
    resetTimeout time.Duration
    failures    int
    lastFailure time.Time
    state       CircuitState
    mutex       sync.RWMutex
}

type CircuitState int

const (
    Closed CircuitState = iota
    Open
    HalfOpen
)

func (cb *CircuitBreaker) Call(fn func() error) error {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    if cb.state == Open {
        if time.Since(cb.lastFailure) > cb.resetTimeout {
            cb.state = HalfOpen
            cb.failures = 0
        } else {
            return fmt.Errorf("circuit breaker is open")
        }
    }
    
    err := fn()
    
    if err != nil {
        cb.failures++
        cb.lastFailure = time.Now()
        
        if cb.failures >= cb.maxFailures {
            cb.state = Open
        }
        
        return err
    }
    
    cb.failures = 0
    cb.state = Closed
    return nil
}
```

## 安全

### API 认证

```go
func AuthMiddleware(secretKey string) gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(401, gin.H{"error": "Missing authorization header"})
            c.Abort()
            return
        }
        
        if !strings.HasPrefix(token, "Bearer ") {
            c.JSON(401, gin.H{"error": "Invalid authorization format"})
            c.Abort()
            return
        }
        
        tokenStr := strings.TrimPrefix(token, "Bearer ")
        claims, err := validateJWT(tokenStr, secretKey)
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user", claims)
        c.Next()
    })
}
```

### 速率限制

```go
func RateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(window/time.Duration(limit)), limit)
    
    return gin.HandlerFunc(func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{
                "error": "Rate limit exceeded",
                "retry_after": window.Seconds(),
            })
            c.Abort()
            return
        }
        c.Next()
    })
}
```

### 输入校验

```go
type VectorRequest struct {
    Vector string `json:"vector" binding:"required,max=500"`
    Format string `json:"format" binding:"omitempty,oneof=standard detailed simplified"`
}

func handleVectorAnalysis(service *CVSSService) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req VectorRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        
        // 额外校验
        if !isValidCVSSVector(req.Vector) {
            c.JSON(400, gin.H{"error": "Invalid CVSS vector format"})
            return
        }
        
        result, err := service.ProcessVector(c.Request.Context(), req.Vector)
        if err != nil {
            c.JSON(500, gin.H{"error": "Processing failed"})
            return
        }
        
        c.JSON(200, result)
    }
}
```

## 监控与可观测性

### 指标采集

```go
type Metrics struct {
    processedVectors prometheus.Counter
    processingTime   prometheus.Histogram
    cacheHits        prometheus.Counter
    cacheMisses      prometheus.Counter
    errors           *prometheus.CounterVec
}

func NewMetrics() *Metrics {
    return &Metrics{
        processedVectors: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "cvss_vectors_processed_total",
            Help: "Total number of CVSS vectors processed",
        }),
        processingTime: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name: "cvss_processing_duration_seconds",
            Help: "Time spent processing CVSS vectors",
            Buckets: prometheus.DefBuckets,
        }),
        cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "cvss_cache_hits_total",
            Help: "Total number of cache hits",
        }),
        cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "cvss_cache_misses_total",
            Help: "Total number of cache misses",
        }),
        errors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "cvss_errors_total",
                Help: "Total number of errors by type",
            },
            []string{"type"},
        ),
    }
}
```

### 健康检查

```go
type HealthChecker struct {
    service *CVSSService
    db      *sql.DB
    redis   *redis.Client
}

func (h *HealthChecker) Check(c *gin.Context) {
    status := gin.H{
        "status": "healthy",
        "timestamp": time.Now().UTC(),
        "version": version.Get(),
    }
    
    checks := make(map[string]interface{})
    
    // 数据库检查
    if err := h.db.Ping(); err != nil {
        checks["database"] = gin.H{"status": "unhealthy", "error": err.Error()}
        status["status"] = "unhealthy"
    } else {
        checks["database"] = gin.H{"status": "healthy"}
    }
    
    // Redis 检查
    if err := h.redis.Ping().Err(); err != nil {
        checks["redis"] = gin.H{"status": "unhealthy", "error": err.Error()}
        status["status"] = "unhealthy"
    } else {
        checks["redis"] = gin.H{"status": "healthy"}
    }
    
    // 服务检查
    testVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    if _, err := h.service.ProcessVector(c.Request.Context(), testVector); err != nil {
        checks["cvss_service"] = gin.H{"status": "unhealthy", "error": err.Error()}
        status["status"] = "unhealthy"
    } else {
        checks["cvss_service"] = gin.H{"status": "healthy"}
    }
    
    status["checks"] = checks
    
    if status["status"] == "unhealthy" {
        c.JSON(503, status)
    } else {
        c.JSON(200, status)
    }
}
```

## 错误处理

### 结构化错误响应

```go
type ErrorResponse struct {
    Error   string            `json:"error"`
    Code    string            `json:"code"`
    Details map[string]string `json:"details,omitempty"`
    TraceID string            `json:"trace_id"`
}

func ErrorHandler() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        c.Next()
        
        if len(c.Errors) > 0 {
            err := c.Errors.Last()
            
            var statusCode int
            var errorCode string

            switch {
            case errors.Is(err.Err, parser.ErrParserMagicHead),
                errors.Is(err.Err, parser.ErrDuplicateMetric):
                statusCode = 400
                errorCode = "PARSE_ERROR"
            case errors.As(err.Err, &cvss.ValidationErrors{}):
                statusCode = 400
                errorCode = "VALIDATION_ERROR"
            default:
                statusCode = 500
                errorCode = "INTERNAL_ERROR"
            }
            
            response := ErrorResponse{
                Error:   err.Error(),
                Code:    errorCode,
                TraceID: getTraceID(c),
            }
            
            c.JSON(statusCode, response)
        }
    })
}
```

## 部署检查清单

### 部署前

- [ ] 负载测试已完成
- [ ] 安全扫描已通过
- [ ] 配置已校验
- [ ] 监控设置已验证
- [ ] 备份流程已测试
- [ ] 回滚计划已准备

### 部署中

- [ ] 蓝绿部署策略
- [ ] 数据库迁移已应用
- [ ] 配置已更新
- [ ] 健康检查通过
- [ ] 指标采集已激活
- [ ] 日志正常流转

### 部署后

- [ ] 性能指标在 SLA 范围内
- [ ] 错误率可接受
- [ ] 用户验收测试已通过
- [ ] 文档已更新
- [ ] 团队已通知
- [ ] 监控告警已配置

## 下一步

生产部署完成后，可参考：

- [监控与告警](/zh/examples/monitoring) - 全面的监控
- [性能优化](/zh/examples/performance) - 高级优化
- [安全加固](/zh/examples/security) - 增强的安全措施

## 相关文档

- [配置参考](/zh/api/getting-started) - 完整的配置指南
- [部署模式](/zh/examples/production) - 高级部署策略
- [运维指南](/zh/examples/production) - 日常运维
