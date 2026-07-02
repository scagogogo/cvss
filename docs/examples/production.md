# Production Deployment

This guide covers enterprise deployment patterns, configuration management, and production best practices for CVSS Skills.

## Overview

Deploying CVSS Skills in production environments requires careful consideration of:

- Scalability and performance
- Security and compliance
- Monitoring and observability
- Error handling and recovery
- Configuration management
- High availability

## Deployment Architectures

### Microservice Architecture

```go
// CVSS Service
type CVSSService struct {
    parser     parser.Parser
    calculator calculator.Calculator
    cache      cache.Cache
    metrics    metrics.Collector
    logger     logger.Logger
}

func NewCVSSService(config *Config) *CVSSService {
    return &CVSSService{
        parser:     parser.NewCvss3xParser(""),
        calculator: calculator.New(),
        cache:      cache.NewRedisCache(config.Redis),
        metrics:    metrics.NewPrometheus(),
        logger:     logger.NewStructured(config.LogLevel),
    }
}

func (s *CVSSService) ProcessVector(ctx context.Context, vectorStr string) (*VectorResult, error) {
    span, ctx := opentracing.StartSpanFromContext(ctx, "cvss.process_vector")
    defer span.Finish()
    
    // Check cache first
    if result, found := s.cache.Get(ctx, vectorStr); found {
        s.metrics.IncrementCacheHits()
        return result, nil
    }
    
    // Parse and calculate
    start := time.Now()
    vector, err := s.parser.Parse(vectorStr)
    if err != nil {
        s.metrics.IncrementErrors("parse_error")
        return nil, fmt.Errorf("failed to parse vector: %w", err)
    }
    
    score, err := s.calculator.Calculate(vector)
    if err != nil {
        s.metrics.IncrementErrors("calculation_error")
        return nil, fmt.Errorf("failed to calculate score: %w", err)
    }
    
    result := &VectorResult{
        Vector:   vectorStr,
        Score:    score,
        Severity: s.calculator.GetSeverityRating(score),
    }
    
    // Cache result
    s.cache.Set(ctx, vectorStr, result, time.Hour)
    s.metrics.RecordProcessingTime(time.Since(start))
    s.metrics.IncrementProcessed()
    
    return result, nil
}
```

### HTTP API Server

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
    
    // Graceful shutdown
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

### Container Deployment

```dockerfile
# Multi-stage build
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cvss-service ./cmd/server

# Final stage
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

## Configuration Management

### Environment-based Configuration

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
    
    // Load from file
    if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
        data, err := ioutil.ReadFile(configFile)
        if err != nil {
            return nil, err
        }
        
        if err := yaml.Unmarshal(data, config); err != nil {
            return nil, err
        }
    }
    
    // Override with environment variables
    if err := env.Parse(config); err != nil {
        return nil, err
    }
    
    return config, nil
}
```

### Kubernetes Deployment

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

## High Availability

### Load Balancing

```yaml
# HAProxy configuration
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

### Circuit Breaker Pattern

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

## Security

### API Authentication

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

### Rate Limiting

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

### Input Validation

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
        
        // Additional validation
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

## Monitoring and Observability

### Metrics Collection

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

### Health Checks

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
    
    // Database check
    if err := h.db.Ping(); err != nil {
        checks["database"] = gin.H{"status": "unhealthy", "error": err.Error()}
        status["status"] = "unhealthy"
    } else {
        checks["database"] = gin.H{"status": "healthy"}
    }
    
    // Redis check
    if err := h.redis.Ping().Err(); err != nil {
        checks["redis"] = gin.H{"status": "unhealthy", "error": err.Error()}
        status["status"] = "unhealthy"
    } else {
        checks["redis"] = gin.H{"status": "healthy"}
    }
    
    // Service check
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

## Error Handling

### Structured Error Responses

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
            
            switch e := err.Err.(type) {
            case *ValidationError:
                statusCode = 400
                errorCode = "VALIDATION_ERROR"
            case *ParseError:
                statusCode = 400
                errorCode = "PARSE_ERROR"
            case *CalculationError:
                statusCode = 422
                errorCode = "CALCULATION_ERROR"
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

## Deployment Checklist

### Pre-deployment

- [ ] Load testing completed
- [ ] Security scanning passed
- [ ] Configuration validated
- [ ] Monitoring setup verified
- [ ] Backup procedures tested
- [ ] Rollback plan prepared

### Deployment

- [ ] Blue-green deployment strategy
- [ ] Database migrations applied
- [ ] Configuration updated
- [ ] Health checks passing
- [ ] Metrics collection active
- [ ] Logs flowing correctly

### Post-deployment

- [ ] Performance metrics within SLA
- [ ] Error rates acceptable
- [ ] User acceptance testing passed
- [ ] Documentation updated
- [ ] Team notified
- [ ] Monitoring alerts configured

## Next Steps

After production deployment, consider:

- [Monitoring and Alerting](/examples/monitoring) - Comprehensive monitoring
- [Performance Optimization](/examples/performance) - Advanced optimization
- [Security Hardening](/examples/security) - Enhanced security measures

## Related Documentation

- [Configuration Reference](/api/getting-started) - Complete configuration guide
- [Deployment Patterns](/examples/production) - Advanced deployment strategies
- [Operations Guide](/examples/production) - Day-to-day operations
