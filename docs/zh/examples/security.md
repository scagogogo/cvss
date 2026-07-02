# 安全示例

本指南演示在安全敏感环境中使用 CVSS Skills 时的安全最佳实践和模式。

## 概述

安全考量包括：

- 输入校验与净化
- 安全数据处理
- 认证与授权
- 审计日志
- 安全通信
- 漏洞管理

## 输入校验

### 全面输入校验

```go
package security

import (
    "fmt"
    "regexp"
    "strings"
    "unicode/utf8"
)

type SecurityValidator struct {
    maxVectorLength int
    allowedChars    *regexp.Regexp
    blockedPatterns []*regexp.Regexp
}

func NewSecurityValidator() *SecurityValidator {
    return &SecurityValidator{
        maxVectorLength: 500,
        allowedChars:    regexp.MustCompile(`^[A-Za-z0-9:/.]+$`),
        blockedPatterns: []*regexp.Regexp{
            regexp.MustCompile(`<script`),           // XSS
            regexp.MustCompile(`javascript:`),       // XSS
            regexp.MustCompile(`on\w+\s*=`),        // 事件处理器
            regexp.MustCompile(`\x00`),             // 空字节
            regexp.MustCompile(`\.\./`),            // 路径遍历
            regexp.MustCompile(`union\s+select`),   // SQL 注入
            regexp.MustCompile(`drop\s+table`),     // SQL 注入
            regexp.MustCompile(`exec\s*\(`),        // 命令注入
        },
    }
}

func (sv *SecurityValidator) ValidateVector(vector string) error {
    // 检查空输入
    if vector == "" {
        return fmt.Errorf("向量不能为空")
    }
    
    // 检查长度
    if len(vector) > sv.maxVectorLength {
        return fmt.Errorf("向量超过最大长度 %d 字符", sv.maxVectorLength)
    }
    
    // 检查合法 UTF-8
    if !utf8.ValidString(vector) {
        return fmt.Errorf("向量包含无效的 UTF-8 字符")
    }
    
    // 检查只含允许的字符
    if !sv.allowedChars.MatchString(vector) {
        return fmt.Errorf("向量包含无效字符")
    }
    
    // 检查被阻止的模式
    for _, pattern := range sv.blockedPatterns {
        if pattern.MatchString(strings.ToLower(vector)) {
            return fmt.Errorf("向量包含潜在恶意内容")
        }
    }
    
    // 校验 CVSS 格式
    if !strings.HasPrefix(vector, "CVSS:3.") {
        return fmt.Errorf("向量必须以 CVSS:3.x 开头")
    }
    
    return nil
}

func (sv *SecurityValidator) SanitizeVector(vector string) string {
    // 移除空字节
    vector = strings.ReplaceAll(vector, "\x00", "")
    
    // 移除控制字符
    var sanitized strings.Builder
    for _, r := range vector {
        if r >= 32 && r < 127 { // 仅可打印 ASCII
            sanitized.WriteRune(r)
        }
    }
    
    return sanitized.String()
}
```

### 速率限制

```go
import (
    "sync"
    "time"
    "golang.org/x/time/rate"
)

type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mutex    sync.RWMutex
    limit    rate.Limit
    burst    int
}

func NewRateLimiter(requestsPerSecond int, burst int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        limit:    rate.Limit(requestsPerSecond),
        burst:    burst,
    }
}

func (rl *RateLimiter) Allow(clientID string) bool {
    rl.mutex.RLock()
    limiter, exists := rl.limiters[clientID]
    rl.mutex.RUnlock()
    
    if !exists {
        rl.mutex.Lock()
        limiter = rate.NewLimiter(rl.limit, rl.burst)
        rl.limiters[clientID] = limiter
        rl.mutex.Unlock()
    }
    
    return limiter.Allow()
}

func (rl *RateLimiter) CleanupExpired() {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    // 移除最近未使用的限流器
    for clientID, limiter := range rl.limiters {
        if limiter.Tokens() == float64(rl.burst) {
            delete(rl.limiters, clientID)
        }
    }
}
```

## 安全数据处理

### 敏感数据保护

```go
type SecureVectorProcessor struct {
    encryptor    *DataEncryptor
    auditor      *AuditLogger
    validator    *SecurityValidator
    rateLimiter  *RateLimiter
}

type DataEncryptor struct {
    key []byte
}

func NewDataEncryptor(key []byte) *DataEncryptor {
    return &DataEncryptor{key: key}
}

func (de *DataEncryptor) Encrypt(data string) (string, error) {
    // 实现应使用 AES-GCM 或类似算法
    // 这是一个简化示例
    return base64.StdEncoding.EncodeToString([]byte(data)), nil
}

func (de *DataEncryptor) Decrypt(encryptedData string) (string, error) {
    // 实现应使用 AES-GCM 解密
    decoded, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    return string(decoded), nil
}

func (svp *SecureVectorProcessor) ProcessVector(ctx context.Context, vector string, clientID string) (*SecureResult, error) {
    // 速率限制
    if !svp.rateLimiter.Allow(clientID) {
        svp.auditor.LogSecurityEvent(ctx, "RATE_LIMIT_EXCEEDED", clientID, vector)
        return nil, fmt.Errorf("超出速率限制")
    }
    
    // 输入校验
    if err := svp.validator.ValidateVector(vector); err != nil {
        svp.auditor.LogSecurityEvent(ctx, "INVALID_INPUT", clientID, vector)
        return nil, fmt.Errorf("校验失败: %w", err)
    }
    
    // 净化输入
    sanitizedVector := svp.validator.SanitizeVector(vector)
    
    // 处理向量
    parsedVector, err := parser.ParseString(sanitizedVector)
    if err != nil {
        svp.auditor.LogSecurityEvent(ctx, "PARSE_ERROR", clientID, sanitizedVector)
        return nil, fmt.Errorf("解析失败: %w", err)
    }
    
    calculator := cvss.NewCalculator(parsedVector)
    score, err := calculator.Calculate()
    if err != nil {
        svp.auditor.LogSecurityEvent(ctx, "CALCULATION_ERROR", clientID, sanitizedVector)
        return nil, fmt.Errorf("计算失败: %w", err)
    }
    
    // 如有需要则加密敏感数据
    encryptedVector, err := svp.encryptor.Encrypt(sanitizedVector)
    if err != nil {
        return nil, fmt.Errorf("加密失败: %w", err)
    }
    
    // 记录成功处理
    svp.auditor.LogProcessingEvent(ctx, clientID, sanitizedVector, score)
    
    return &SecureResult{
        EncryptedVector: encryptedVector,
        Score:          score,
        Severity:       calculator.GetSeverityRating(score).String(),
        ProcessedAt:    time.Now(),
        ClientID:       clientID,
    }, nil
}

type SecureResult struct {
    EncryptedVector string    `json:"encrypted_vector"`
    Score          float64   `json:"score"`
    Severity       string    `json:"severity"`
    ProcessedAt    time.Time `json:"processed_at"`
    ClientID       string    `json:"client_id"`
}
```

## 认证与授权

### JWT 认证

```go
import (
    "github.com/golang-jwt/jwt/v4"
    "crypto/rsa"
)

type AuthService struct {
    publicKey  *rsa.PublicKey
    privateKey *rsa.PrivateKey
    issuer     string
}

type Claims struct {
    UserID      string   `json:"user_id"`
    Permissions []string `json:"permissions"`
    jwt.RegisteredClaims
}

func NewAuthService(publicKey, privateKey *rsa.Key, issuer string) *AuthService {
    return &AuthService{
        publicKey:  publicKey,
        privateKey: privateKey,
        issuer:     issuer,
    }
}

func (as *AuthService) ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
        }
        return as.publicKey, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, fmt.Errorf("无效令牌")
}

func (as *AuthService) HasPermission(claims *Claims, permission string) bool {
    for _, p := range claims.Permissions {
        if p == permission || p == "admin" {
            return true
        }
    }
    return false
}

// HTTP 处理器中间件
func (as *AuthService) AuthMiddleware(requiredPermission string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "缺少授权头", http.StatusUnauthorized)
                return
            }
            
            tokenString := strings.TrimPrefix(authHeader, "Bearer ")
            claims, err := as.ValidateToken(tokenString)
            if err != nil {
                http.Error(w, "无效令牌", http.StatusUnauthorized)
                return
            }
            
            if !as.HasPermission(claims, requiredPermission) {
                http.Error(w, "权限不足", http.StatusForbidden)
                return
            }
            
            // 将 claims 加入上下文
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## 审计日志

### 全面审计追踪

```go
type AuditLogger struct {
    logger *logrus.Logger
    db     *sql.DB
}

type AuditEvent struct {
    ID          string    `json:"id"`
    Timestamp   time.Time `json:"timestamp"`
    EventType   string    `json:"event_type"`
    UserID      string    `json:"user_id"`
    ClientID    string    `json:"client_id"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    Result      string    `json:"result"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
    Details     string    `json:"details"`
    Severity    string    `json:"severity"`
}

func NewAuditLogger(logger *logrus.Logger, db *sql.DB) *AuditLogger {
    return &AuditLogger{
        logger: logger,
        db:     db,
    }
}

func (al *AuditLogger) LogSecurityEvent(ctx context.Context, eventType, clientID, details string) {
    event := &AuditEvent{
        ID:        generateUUID(),
        Timestamp: time.Now().UTC(),
        EventType: eventType,
        ClientID:  clientID,
        Action:    "CVSS_PROCESSING",
        Resource:  "CVSS_VECTOR",
        Result:    "SECURITY_VIOLATION",
        Details:   details,
        Severity:  "HIGH",
    }
    
    // 提取额外上下文
    if claims := ctx.Value("claims"); claims != nil {
        if c, ok := claims.(*Claims); ok {
            event.UserID = c.UserID
        }
    }
    
    if req := ctx.Value("request"); req != nil {
        if r, ok := req.(*http.Request); ok {
            event.IPAddress = getClientIP(r)
            event.UserAgent = r.UserAgent()
        }
    }
    
    // 记录到结构化日志
    al.logger.WithFields(logrus.Fields{
        "audit_event": event,
    }).Warn("检测到安全事件")
    
    // 存入数据库
    al.storeAuditEvent(event)
}

func (al *AuditLogger) LogProcessingEvent(ctx context.Context, clientID, vector string, score float64) {
    event := &AuditEvent{
        ID:        generateUUID(),
        Timestamp: time.Now().UTC(),
        EventType: "PROCESSING_SUCCESS",
        ClientID:  clientID,
        Action:    "CVSS_PROCESSING",
        Resource:  "CVSS_VECTOR",
        Result:    "SUCCESS",
        Details:   fmt.Sprintf("向量处理成功，分数: %.1f", score),
        Severity:  "INFO",
    }
    
    al.logger.WithFields(logrus.Fields{
        "audit_event": event,
    }).Info("向量处理成功")
    
    al.storeAuditEvent(event)
}

func (al *AuditLogger) storeAuditEvent(event *AuditEvent) {
    query := `
        INSERT INTO audit_events (
            id, timestamp, event_type, user_id, client_id, action, 
            resource, result, ip_address, user_agent, details, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    
    _, err := al.db.Exec(query,
        event.ID, event.Timestamp, event.EventType, event.UserID,
        event.ClientID, event.Action, event.Resource, event.Result,
        event.IPAddress, event.UserAgent, event.Details, event.Severity,
    )
    
    if err != nil {
        al.logger.WithError(err).Error("存储审计事件失败")
    }
}
```

## 安全通信

### TLS 配置

```go
import (
    "crypto/tls"
    "crypto/x509"
)

func CreateSecureTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }
}

func CreateSecureHTTPServer(handler http.Handler, certFile, keyFile string) *http.Server {
    tlsConfig := CreateSecureTLSConfig()
    
    server := &http.Server{
        Addr:         ":8443",
        Handler:      handler,
        TLSConfig:    tlsConfig,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    return server
}
```

### 证书校验

```go
func ValidateClientCertificate(cert *x509.Certificate, caCert *x509.Certificate) error {
    // 检查证书是否过期
    now := time.Now()
    if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
        return fmt.Errorf("证书已过期或尚未生效")
    }
    
    // 校验证书链
    roots := x509.NewCertPool()
    roots.AddCert(caCert)
    
    opts := x509.VerifyOptions{
        Roots: roots,
    }
    
    _, err := cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("证书校验失败: %w", err)
    }
    
    return nil
}
```

## 漏洞管理

### 安全扫描集成

```go
type SecurityScanner struct {
    vulnerabilityDB *VulnerabilityDB
    alertManager    *AlertManager
}

type VulnerabilityDB struct {
    db *sql.DB
}

func (vs *SecurityScanner) ScanVector(vector string) (*SecurityScanResult, error) {
    // 解析向量以提取组件
    parsedVector, err := parser.ParseString(vector)
    if err != nil {
        return nil, err
    }
    
    // 检查已知漏洞模式
    threats := vs.checkKnownThreats(parsedVector)
    
    // 分析风险等级
    riskLevel := vs.assessRiskLevel(parsedVector, threats)
    
    // 生成建议
    recommendations := vs.generateRecommendations(parsedVector, threats)
    
    result := &SecurityScanResult{
        Vector:          vector,
        Threats:         threats,
        RiskLevel:       riskLevel,
        Recommendations: recommendations,
        ScanTime:        time.Now(),
    }
    
    // 高风险发现时告警
    if riskLevel == "HIGH" || riskLevel == "CRITICAL" {
        vs.alertManager.SendAlert(result)
    }
    
    return result, nil
}

type SecurityScanResult struct {
    Vector          string              `json:"vector"`
    Threats         []ThreatIndicator   `json:"threats"`
    RiskLevel       string              `json:"risk_level"`
    Recommendations []string            `json:"recommendations"`
    ScanTime        time.Time           `json:"scan_time"`
}

type ThreatIndicator struct {
    Type        string  `json:"type"`
    Severity    string  `json:"severity"`
    Description string  `json:"description"`
    Confidence  float64 `json:"confidence"`
}
```

## 安全测试

### 安全测试套件

```go
func TestSecurityValidation(t *testing.T) {
    validator := NewSecurityValidator()
    
    maliciousInputs := []struct {
        name  string
        input string
    }{
        {"XSS 脚本", "<script>alert('xss')</script>"},
        {"SQL 注入", "'; DROP TABLE users; --"},
        {"路径遍历", "../../../etc/passwd"},
        {"空字节", "CVSS:3.1\x00/AV:N"},
        {"命令注入", "CVSS:3.1; rm -rf /"},
        {"Unicode 攻击", "CVSS:3.1‮/AV:N"},
        {"超长输入", strings.Repeat("A", 10000)},
    }
    
    for _, test := range maliciousInputs {
        t.Run(test.name, func(t *testing.T) {
            err := validator.ValidateVector(test.input)
            assert.Error(t, err, "应拒绝恶意输入: %s", test.input)
        })
    }
}

func TestRateLimiting(t *testing.T) {
    limiter := NewRateLimiter(5, 10) // 每秒 5 个请求，突发 10
    
    clientID := "test-client"
    
    // 应允许初始突发
    for i := 0; i < 10; i++ {
        assert.True(t, limiter.Allow(clientID), "应允许请求 %d", i+1)
    }
    
    // 应拒绝额外请求
    assert.False(t, limiter.Allow(clientID), "突发后应拒绝请求")
    
    // 等待后重试
    time.Sleep(200 * time.Millisecond)
    assert.True(t, limiter.Allow(clientID), "等待后应允许请求")
}
```

## 安全监控

### 实时安全监控

```go
type SecurityMonitor struct {
    alertThresholds map[string]int
    eventCounts     map[string]int
    mutex          sync.RWMutex
    alertManager   *AlertManager
}

func NewSecurityMonitor() *SecurityMonitor {
    return &SecurityMonitor{
        alertThresholds: map[string]int{
            "INVALID_INPUT":        10,
            "RATE_LIMIT_EXCEEDED": 50,
            "AUTH_FAILURE":        5,
        },
        eventCounts: make(map[string]int),
    }
}

func (sm *SecurityMonitor) RecordSecurityEvent(eventType string) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()
    
    sm.eventCounts[eventType]++
    
    if threshold, exists := sm.alertThresholds[eventType]; exists {
        if sm.eventCounts[eventType] >= threshold {
            sm.alertManager.SendSecurityAlert(eventType, sm.eventCounts[eventType])
            sm.eventCounts[eventType] = 0 // 重置计数器
        }
    }
}

func (sm *SecurityMonitor) GetSecurityMetrics() map[string]int {
    sm.mutex.RLock()
    defer sm.mutex.RUnlock()
    
    metrics := make(map[string]int)
    for k, v := range sm.eventCounts {
        metrics[k] = v
    }
    
    return metrics
}
```

## 最佳实践

### 安全检查清单

1. **输入校验**
   - 对所有输入按严格模式校验
   - 处理前净化输入
   - 实施长度限制
   - 检查恶意模式

2. **认证与授权**
   - 使用强认证机制
   - 实施适当的授权检查
   - 使用安全的令牌处理
   - 对每个操作校验权限

3. **数据保护**
   - 对静态和传输中的敏感数据加密
   - 使用安全的密钥管理
   - 实施适当的数据留存策略
   - 净化日志和错误消息

4. **监控与日志**
   - 记录所有安全相关事件
   - 实施实时监控
   - 为可疑活动设置告警
   - 维护审计追踪

5. **网络安全**
   - 所有通信使用 TLS
   - 实施适当的证书校验
   - 配置安全的密码套件
   - 使用网络分段

## 下一步

实施安全措施后：

- [监控](/zh/examples/monitoring) - 安全监控集成
- [风险评估](/zh/examples/risk-assessment) - 风险等级分析
- [生产环境](/zh/examples/production) - 生产环境加固检查清单

## 相关文档

- [错误处理](/zh/api/error-handling) - 安全的错误处理
- [性能](/zh/examples/performance) - 负载下的性能
- [监控](/zh/examples/monitoring) - 安全监控
