# Monitoring and Alerting

This guide covers comprehensive monitoring, alerting, and observability strategies for CVSS Skills in production environments.

## Overview

Effective monitoring ensures:

- System health and performance visibility
- Proactive issue detection
- Performance optimization insights
- Compliance and audit trails
- Incident response capabilities

## Metrics Collection

### Application Metrics

```go
type CVSSMetrics struct {
    // Processing metrics
    VectorsProcessed    prometheus.Counter
    ProcessingDuration  prometheus.Histogram
    ProcessingErrors    *prometheus.CounterVec
    
    // Cache metrics
    CacheHits          prometheus.Counter
    CacheMisses        prometheus.Counter
    CacheSize          prometheus.Gauge
    
    // Business metrics
    SeverityDistribution *prometheus.CounterVec
    VectorTypes         *prometheus.CounterVec
    
    // System metrics
    MemoryUsage        prometheus.Gauge
    GoroutineCount     prometheus.Gauge
    GCDuration         prometheus.Histogram
}

func NewCVSSMetrics() *CVSSMetrics {
    metrics := &CVSSMetrics{
        VectorsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "cvss_vectors_processed_total",
            Help: "Total number of CVSS vectors processed",
        }),
        ProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name: "cvss_processing_duration_seconds",
            Help: "Time spent processing CVSS vectors",
            Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
        }),
        ProcessingErrors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "cvss_processing_errors_total",
                Help: "Total number of processing errors by type",
            },
            []string{"error_type"},
        ),
        SeverityDistribution: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "cvss_severity_distribution_total",
                Help: "Distribution of CVSS severity levels",
            },
            []string{"severity"},
        ),
    }
    
    // Register metrics
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

### System Metrics Collection

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

## Logging

### Structured Logging

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
    }).Info("Vector processed successfully")
}

func (l *Logger) LogError(ctx context.Context, err error, vector string) {
    l.logger.WithFields(logrus.Fields{
        "trace_id":   getTraceID(ctx),
        "error":      err.Error(),
        "vector":     vector,
        "error_type": categorizeError(err),
        "timestamp":  time.Now().UTC(),
        "component":  "cvss_processor",
    }).Error("Vector processing failed")
}
```

### Log Aggregation

```yaml
# Fluentd configuration
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

## Alerting Rules

### Prometheus Alerting Rules

```yaml
groups:
- name: cvss-service
  rules:
  - alert: CVSSHighErrorRate
    expr: rate(cvss_processing_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "High error rate in CVSS processing"
      description: "Error rate is {{ $value }} errors per second"

  - alert: CVSSHighLatency
    expr: histogram_quantile(0.95, rate(cvss_processing_duration_seconds_bucket[5m])) > 1.0
    for: 5m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "High latency in CVSS processing"
      description: "95th percentile latency is {{ $value }} seconds"

  - alert: CVSSServiceDown
    expr: up{job="cvss-service"} == 0
    for: 1m
    labels:
      severity: critical
      service: cvss-skills
    annotations:
      summary: "CVSS service is down"
      description: "CVSS service has been down for more than 1 minute"

  - alert: CVSSHighMemoryUsage
    expr: cvss_memory_usage_bytes > 1073741824  # 1GB
    for: 5m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "High memory usage in CVSS service"
      description: "Memory usage is {{ $value | humanizeBytes }}"

  - alert: CVSSCacheMissRate
    expr: rate(cvss_cache_misses_total[5m]) / (rate(cvss_cache_hits_total[5m]) + rate(cvss_cache_misses_total[5m])) > 0.8
    for: 10m
    labels:
      severity: warning
      service: cvss-skills
    annotations:
      summary: "High cache miss rate"
      description: "Cache miss rate is {{ $value | humanizePercentage }}"
```

### Alert Manager Configuration

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
    subject: 'CRITICAL: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}
  pagerduty_configs:
  - service_key: 'your-pagerduty-key'

- name: 'cvss-team'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    channel: '#cvss-alerts'
    title: 'CVSS Service Alert'
    text: '{{ .CommonAnnotations.summary }}'
```

## Dashboards

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "CVSS Skills Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cvss_vectors_processed_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(cvss_processing_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(cvss_processing_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cvss_processing_errors_total[5m])",
            "legendFormat": "Errors/sec"
          }
        ]
      },
      {
        "title": "Severity Distribution",
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

## Health Checks

### Comprehensive Health Monitoring

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
    
    // Check database
    start := time.Now()
    if err := hm.db.Ping(); err != nil {
        status.Components["database"] = ComponentHealth{
            Status: "unhealthy",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["database"] = ComponentHealth{
            Status: "healthy",
            ResponseTime: time.Since(start),
        }
    }
    
    // Check Redis
    start = time.Now()
    if err := hm.redis.Ping().Err(); err != nil {
        status.Components["redis"] = ComponentHealth{
            Status: "unhealthy",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["redis"] = ComponentHealth{
            Status: "healthy",
            ResponseTime: time.Since(start),
        }
    }
    
    // Check CVSS processing
    start = time.Now()
    testVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    if _, err := hm.service.ProcessVector(context.Background(), testVector); err != nil {
        status.Components["cvss_processing"] = ComponentHealth{
            Status: "unhealthy",
            Error:  err.Error(),
            ResponseTime: time.Since(start),
        }
    } else {
        status.Components["cvss_processing"] = ComponentHealth{
            Status: "healthy",
            ResponseTime: time.Since(start),
        }
    }
    
    // Determine overall status
    status.Overall = "healthy"
    for _, component := range status.Components {
        if component.Status != "healthy" {
            status.Overall = "unhealthy"
            break
        }
    }
    
    hm.status = status
    hm.lastCheck = time.Now()
    
    return status
}
```

## Distributed Tracing

### OpenTelemetry Integration

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
    
    // Parse vector
    ctx, parseSpan := tracer.Start(ctx, "parse_vector")
    vector, err := s.parser.Parse(vectorStr)
    parseSpan.End()
    
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "Failed to parse vector")
        return nil, err
    }
    
    // Calculate score
    ctx, calcSpan := tracer.Start(ctx, "calculate_score")
    score, err := s.calculator.Calculate(vector)
    calcSpan.End()
    
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "Failed to calculate score")
        return nil, err
    }
    
    span.SetAttributes(
        attribute.Float64("cvss.score", score),
        attribute.String("cvss.severity", s.calculator.GetSeverityRating(score)),
    )
    
    return &VectorResult{
        Vector:   vectorStr,
        Score:    score,
        Severity: s.calculator.GetSeverityRating(score),
    }, nil
}
```

## Performance Monitoring

### SLA Monitoring

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
                Name:        "Service Availability",
                Threshold:   99.9,
                Window:      24 * time.Hour,
                Description: "Service should be available 99.9% of the time",
            },
            "latency_p95": {
                Name:        "95th Percentile Latency",
                Threshold:   500, // milliseconds
                Window:      5 * time.Minute,
                Description: "95% of requests should complete within 500ms",
            },
            "error_rate": {
                Name:        "Error Rate",
                Threshold:   1.0, // percentage
                Window:      5 * time.Minute,
                Description: "Error rate should be below 1%",
            },
        },
    }
}

func (sla *SLAMonitor) CheckSLA(target string) (bool, float64, error) {
    slaTarget, exists := sla.targets[target]
    if !exists {
        return false, 0, fmt.Errorf("unknown SLA target: %s", target)
    }
    
    switch target {
    case "availability":
        return sla.checkAvailability(slaTarget)
    case "latency_p95":
        return sla.checkLatency(slaTarget)
    case "error_rate":
        return sla.checkErrorRate(slaTarget)
    default:
        return false, 0, fmt.Errorf("unsupported SLA target: %s", target)
    }
}
```

## Incident Response

### Automated Incident Detection

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
        Status:      "open",
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    
    // Log incident
    id.logger.LogIncident(incident)
    
    // Auto-remediation for known issues
    if remediation := id.getAutoRemediation(alert); remediation != nil {
        if err := remediation.Execute(); err != nil {
            id.logger.LogError(context.Background(), err, "Auto-remediation failed")
        } else {
            incident.Status = "auto-resolved"
            incident.Resolution = "Auto-remediated"
            incident.UpdatedAt = time.Now()
        }
    }
    
    // Escalate if needed
    if incident.Status == "open" {
        id.escalation.Escalate(incident)
    }
}
```

## Next Steps

After implementing monitoring, consider:

- [Performance Optimization](/examples/performance) - Advanced optimization
- [Security Monitoring](/examples/security) - Security-focused monitoring
- [Risk Assessment](/examples/risk-assessment) - Risk-level analysis

## Related Documentation

- [Performance Guide](/api/performance) - Performance characteristics
- [Error Handling](/api/error-handling) - Diagnosing failures
- [Testing](/api/testing) - Validating monitoring code
