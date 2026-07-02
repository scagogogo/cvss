# 监控和告警

本指南涵盖生产环境中 CVSS Skills 的全面监控、告警和可观测性策略。

## 概述

有效的监控确保：

- 系统健康和性能可见性
- 主动问题检测
- 性能优化洞察
- 合规性和审计跟踪
- 事件响应能力

## 指标收集

### 应用程序指标

```go
type CVSSMetrics struct {
    // 处理指标
    VectorsProcessed    prometheus.Counter
    ProcessingDuration  prometheus.Histogram
    ProcessingErrors    *prometheus.CounterVec
    
    // 缓存指标
    CacheHits          prometheus.Counter
    CacheMisses        prometheus.Counter
    CacheSize          prometheus.Gauge
    
    // 业务指标
    SeverityDistribution *prometheus.CounterVec
    VectorTypes         *prometheus.CounterVec
    
    // 系统指标
    MemoryUsage        prometheus.Gauge
    GoroutineCount     prometheus.Gauge
    GCDuration         prometheus.Histogram
}

func NewCVSSMetrics() *CVSSMetrics {
    metrics := &CVSSMetrics{
        VectorsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "cvss_vectors_processed_total",
            Help: "处理的 CVSS 向量总数",
        }),
        ProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name: "cvss_processing_duration_seconds",
            Help: "处理 CVSS 向量的时间",
            Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
        }),
        ProcessingErrors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "cvss_processing_errors_total",
                Help: "按类型分类的处理错误总数",
            },
            []string{"error_type"},
        ),
        SeverityDistribution: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "cvss_severity_distribution_total",
                Help: "CVSS 严重性级别分布",
            },
            []string{"severity"},
        ),
    }
    
    // 注册指标
    prometheus.MustRegister(
        metrics.VectorsProcessed,
        metrics.ProcessingDuration,
        metrics.ProcessingErrors,
        metrics.SeverityDistribution,
    )
    
    return metrics
}

func (m *CVSSMetrics) RecordProcessing(duration time.Duration, severity string, err error) {
    m.VectorsProcessed.Inc()
    m.ProcessingDuration.Observe(duration.Seconds())
    m.SeverityDistribution.WithLabelValues(severity).Inc()
    
    if err != nil {
        errorType := categorizeError(err)
        m.ProcessingErrors.WithLabelValues(errorType).Inc()
    }
}
```

### 系统指标收集

```go
func (m *CVSSMetrics) CollectSystemMetrics() {
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        
        for range ticker.C {
            var memStats runtime.MemStats
            runtime.ReadMemStats(&memStats)
            
            m.MemoryUsage.Set(float64(memStats.Alloc))
            m.GoroutineCount.Set(float64(runtime.NumGoroutine()))
        }
    }()
}
```

## 日志记录

### 结构化日志记录

```go
type Logger struct {
    logger *logrus.Logger
}

func NewLogger(level string) *Logger {
    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    
    logLevel, err := logrus.ParseLevel(level)
    if err != nil {
        logLevel = logrus.InfoLevel
    }
    logger.SetLevel(logLevel)
    
    return &Logger{logger: logger}
}

func (l *Logger) LogVectorProcessing(ctx context.Context, vector string, score float64, duration time.Duration) {
    l.logger.WithFields(logrus.Fields{
        "trace_id":   getTraceID(ctx),
        "vector":     vector,
        "score":      score,
        "duration":   duration.Milliseconds(),
        "severity":   getSeverityFromScore(score),
        "timestamp":  time.Now().UTC(),
        "component":  "cvss_processor",
    }).Info("向量处理成功")
}

func (l *Logger) LogError(ctx context.Context, err error, vector string) {
    l.logger.WithFields(logrus.Fields{
        "trace_id":   getTraceID(ctx),
        "error":      err.Error(),
        "vector":     vector,
        "error_type": categorizeError(err),
        "timestamp":  time.Now().UTC(),
        "component":  "cvss_processor",
    }).Error("向量处理失败")
}
```

### 日志聚合

```yaml
# Fluentd 配置
<source>
  @type tail
  path /var/log/cvss-service/*.log
  pos_file /var/log/fluentd/cvss-service.log.pos
  tag cvss.service
  format json
  time_key timestamp
  time_format %Y-%m-%dT%H:%M:%S.%LZ
</source>

<filter cvss.service>
  @type record_transformer
  <record>
    service cvss-skills
    environment ${ENV}
    version ${VERSION}
  </record>
</filter>

<match cvss.service>
  @type elasticsearch
  host elasticsearch.monitoring.svc.cluster.local
  port 9200
  index_name cvss-logs
  type_name _doc
</match>
```

## 告警规则

### Prometheus 告警规则

```yaml
groups:
- name: cvss-service
  rules:
  - alert: CVSS高错误率
    expr: rate(cvss_processing_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "CVSS 处理中的高错误率"
      description: "错误率为每秒 {{ $value }} 个错误"

  - alert: CVSS高延迟
    expr: histogram_quantile(0.95, rate(cvss_processing_duration_seconds_bucket[5m])) > 1.0
    for: 5m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "CVSS 处理中的高延迟"
      description: "95% 延迟为 {{ $value }} 秒"

  - alert: CVSS服务宕机
    expr: up{job="cvss-service"} == 0
    for: 1m
    labels:
      severity: critical
      service: cvss-skills
    annotations:
      summary: "CVSS 服务宕机"
      description: "CVSS 服务已宕机超过 1 分钟"

  - alert: CVSS高内存使用
    expr: cvss_memory_usage_bytes > 1073741824  # 1GB
    for: 5m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "CVSS 服务中的高内存使用"
      description: "内存使用为 {{ $value | humanizeBytes }}"

  - alert: CVSS缓存未命中率高
    expr: rate(cvss_cache_misses_total[5m]) / (rate(cvss_cache_hits_total[5m]) + rate(cvss_cache_misses_total[5m])) > 0.8
    for: 10m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "高缓存未命中率"
      description: "缓存未命中率为 {{ $value | humanizePercentage }}"
```

### Alert Manager 配置

```yaml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alerts@company.com'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
  - match:
      service: cvss-skills
    receiver: 'cvss-team'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://slack-webhook/alerts'

- name: 'critical-alerts'
  email_configs:
  - to: 'oncall@company.com'
    subject: '严重: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      告警: {{ .Annotations.summary }}
      描述: {{ .Annotations.description }}
      {{ end }}
  pagerduty_configs:
  - service_key: 'your-pagerduty-key'

- name: 'cvss-team'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    channel: '#cvss-alerts'
    title: 'CVSS 服务告警'
    text: '{{ .CommonAnnotations.summary }}'
```

## 仪表板

### Grafana 仪表板

```json
{
  "dashboard": {
    "title": "CVSS Skills 监控",
    "panels": [
      {
        "title": "请求速率",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cvss_vectors_processed_total[5m])",
            "legendFormat": "请求/秒"
          }
        ]
      },
      {
        "title": "响应时间",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(cvss_processing_duration_seconds_bucket[5m]))",
            "legendFormat": "50% 分位数"
          },
          {
            "expr": "histogram_quantile(0.95, rate(cvss_processing_duration_seconds_bucket[5m]))",
            "legendFormat": "95% 分位数"
          }
        ]
      },
      {
        "title": "错误率",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cvss_processing_errors_total[5m])",
            "legendFormat": "错误/秒"
          }
        ]
      },
      {
        "title": "严重性分布",
        "type": "pie",
        "targets": [
          {
            "expr": "cvss_severity_distribution_total",
            "legendFormat": "{{ severity }}"
          }
        ]
      }
    ]
  }
}
```

## 健康检查

### 全面健康监控

```go
type HealthMonitor struct {
    service    *CVSSService
    db         *sql.DB
    redis      *redis.Client
    lastCheck  time.Time
    status     HealthStatus
    mutex      sync.RWMutex
}

type HealthStatus struct {
    Overall    string                 `json:"overall"`
    Components map[string]ComponentHealth `json:"components"`
    Timestamp  time.Time              `json:"timestamp"`
    Uptime     time.Duration          `json:"uptime"`
}

type ComponentHealth struct {
    Status      string        `json:"status"`
    ResponseTime time.Duration `json:"response_time"`
    Error       string        `json:"error,omitempty"`
}

func (hm *HealthMonitor) CheckHealth() HealthStatus {
    hm.mutex.Lock()
    defer hm.mutex.Unlock()
    
    status := HealthStatus{
        Components: make(map[string]ComponentHealth),
        Timestamp:  time.Now(),
        Uptime:     time.Since(startTime),
    }
    
    // 检查数据库
    start := time.Now()
    if err := hm.db.Ping(); err != nil {
        status.Components["database"] = ComponentHealth{
            Status: "不健康",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["database"] = ComponentHealth{
            Status: "健康",
            ResponseTime: time.Since(start),
        }
    }
    
    // 检查 Redis
    start = time.Now()
    if err := hm.redis.Ping().Err(); err != nil {
        status.Components["redis"] = ComponentHealth{
            Status: "不健康",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["redis"] = ComponentHealth{
            Status: "健康",
            ResponseTime: time.Since(start),
        }
    }
    
    // 检查 CVSS 处理
    start = time.Now()
    testVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    if _, err := hm.service.ProcessVector(context.Background(), testVector); err != nil {
        status.Components["cvss_processing"] = ComponentHealth{
            Status: "不健康",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["cvss_processing"] = ComponentHealth{
            Status: "健康",
            ResponseTime: time.Since(start),
        }
    }
    
    // 确定整体状态
    status.Overall = "健康"
    for _, component := range status.Components {
        if component.Status != "健康" {
            status.Overall = "不健康"
            break
        }
    }
    
    hm.status = status
    hm.lastCheck = time.Now()
    
    return status
}
```

## 分布式追踪

### OpenTelemetry 集成

```go
func initTracing() {
    exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://jaeger:14268/api/traces")))
    if err != nil {
        log.Fatal(err)
    }
    
    tp := trace.NewTracerProvider(
        trace.WithBatcher(exporter),
        trace.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceNameKey.String("cvss-skills"),
            semconv.ServiceVersionKey.String(version.Get()),
        )),
    )
    
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.TraceContext{})
}

func (s *CVSSService) ProcessVectorWithTracing(ctx context.Context, vectorStr string) (*VectorResult, error) {
    tracer := otel.Tracer("cvss-skills")
    ctx, span := tracer.Start(ctx, "process_vector")
    defer span.End()
    
    span.SetAttributes(
        attribute.String("cvss.vector", vectorStr),
        attribute.String("cvss.version", "3.1"),
    )
    
    // 解析向量
    ctx, parseSpan := tracer.Start(ctx, "parse_vector")
    vector, err := parser.ParseString(vectorStr)
    parseSpan.End()

    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "解析向量失败")
        return nil, err
    }

    // 计算分数（Calculator 在构造时绑定向量）
    ctx, calcSpan := tracer.Start(ctx, "calculate_score")
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    calcSpan.End()

    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "计算分数失败")
        return nil, err
    }

    span.SetAttributes(
        attribute.Float64("cvss.score", score),
        attribute.String("cvss.severity", calculator.GetSeverityRating(score).String()),
    )

    return &VectorResult{
        Vector:   vectorStr,
        Score:    score,
        Severity: calculator.GetSeverityRating(score),
    }, nil
}
```

## 性能监控

### SLA 监控

```go
type SLAMonitor struct {
    targets map[string]SLATarget
    metrics *CVSSMetrics
}

type SLATarget struct {
    Name        string
    Threshold   float64
    Window      time.Duration
    Description string
}

func NewSLAMonitor(metrics *CVSSMetrics) *SLAMonitor {
    return &SLAMonitor{
        metrics: metrics,
        targets: map[string]SLATarget{
            "availability": {
                Name:        "服务可用性",
                Threshold:   99.9,
                Window:      24 * time.Hour,
                Description: "服务应在 99.9% 的时间内可用",
            },
            "latency_p95": {
                Name:        "95% 延迟",
                Threshold:   500, // 毫秒
                Window:      5 * time.Minute,
                Description: "95% 的请求应在 500ms 内完成",
            },
            "error_rate": {
                Name:        "错误率",
                Threshold:   1.0, // 百分比
                Window:      5 * time.Minute,
                Description: "错误率应低于 1%",
            },
        },
    }
}

func (sla *SLAMonitor) CheckSLA(target string) (bool, float64, error) {
    slaTarget, exists := sla.targets[target]
    if !exists {
        return false, 0, fmt.Errorf("未知的 SLA 目标: %s", target)
    }
    
    switch target {
    case "availability":
        return sla.checkAvailability(slaTarget)
    case "latency_p95":
        return sla.checkLatency(slaTarget)
    case "error_rate":
        return sla.checkErrorRate(slaTarget)
    default:
        return false, 0, fmt.Errorf("不支持的 SLA 目标: %s", target)
    }
}
```

## 事件响应

### 自动化事件检测

```go
type IncidentDetector struct {
    alertManager *AlertManager
    escalation   *EscalationPolicy
    logger       *Logger
}

func (id *IncidentDetector) HandleAlert(alert Alert) {
    incident := &Incident{
        ID:          generateIncidentID(),
        Alert:       alert,
        Severity:    alert.Severity,
        Status:      "开放",
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    
    // 记录事件
    id.logger.LogIncident(incident)
    
    // 已知问题的自动修复
    if remediation := id.getAutoRemediation(alert); remediation != nil {
        if err := remediation.Execute(); err != nil {
            id.logger.LogError(context.Background(), err, "自动修复失败")
        } else {
            incident.Status = "自动解决"
            incident.Resolution = "自动修复"
            incident.UpdatedAt = time.Now()
        }
    }
    
    // 如果需要则升级
    if incident.Status == "开放" {
        id.escalation.Escalate(incident)
    }
}
```

## 下一步

实施监控后，考虑：

- [性能优化](/zh/examples/performance) - 高级优化
- [安全监控](/zh/examples/edge-cases) - 安全重点监控
- [容量规划](/zh/examples/performance) - 资源规划

## 相关文档

- [指标参考](/zh/examples/monitoring) - 完整的指标文档
- [告警手册](/zh/examples/monitoring) - 常见告警模式
- [故障排除指南](/zh/api/cvss/) - 常见问题和解决方案
