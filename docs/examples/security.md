# Security Examples

This guide demonstrates security best practices and patterns when using CVSS Skills in security-sensitive environments.

## Overview

Security considerations include:

- Input validation and sanitization
- Secure data handling
- Authentication and authorization
- Audit logging
- Secure communication
- Vulnerability management

## Input Validation

### Comprehensive Input Validation

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
            regexp.MustCompile(`on\w+\s*=`),        // Event handlers
            regexp.MustCompile(`\x00`),             // Null bytes
            regexp.MustCompile(`\.\./`),            // Path traversal
            regexp.MustCompile(`union\s+select`),   // SQL injection
            regexp.MustCompile(`drop\s+table`),     // SQL injection
            regexp.MustCompile(`exec\s*\(`),        // Command injection
        },
    }
}

func (sv *SecurityValidator) ValidateVector(vector string) error {
    // Check for empty input
    if vector == "" {
        return fmt.Errorf("vector cannot be empty")
    }
    
    // Check length
    if len(vector) > sv.maxVectorLength {
        return fmt.Errorf("vector exceeds maximum length of %d characters", sv.maxVectorLength)
    }
    
    // Check for valid UTF-8
    if !utf8.ValidString(vector) {
        return fmt.Errorf("vector contains invalid UTF-8 characters")
    }
    
    // Check for allowed characters only
    if !sv.allowedChars.MatchString(vector) {
        return fmt.Errorf("vector contains invalid characters")
    }
    
    // Check for blocked patterns
    for _, pattern := range sv.blockedPatterns {
        if pattern.MatchString(strings.ToLower(vector)) {
            return fmt.Errorf("vector contains potentially malicious content")
        }
    }
    
    // Validate CVSS format
    if !strings.HasPrefix(vector, "CVSS:3.") {
        return fmt.Errorf("vector must start with CVSS:3.x")
    }
    
    return nil
}

func (sv *SecurityValidator) SanitizeVector(vector string) string {
    // Remove null bytes
    vector = strings.ReplaceAll(vector, "\x00", "")
    
    // Remove control characters
    var sanitized strings.Builder
    for _, r := range vector {
        if r >= 32 && r < 127 { // Printable ASCII only
            sanitized.WriteRune(r)
        }
    }
    
    return sanitized.String()
}
```

### Rate Limiting

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
    
    // Remove limiters that haven't been used recently
    for clientID, limiter := range rl.limiters {
        if limiter.Tokens() == float64(rl.burst) {
            delete(rl.limiters, clientID)
        }
    }
}
```

## Secure Data Handling

### Sensitive Data Protection

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
    // Implementation would use AES-GCM or similar
    // This is a simplified example
    return base64.StdEncoding.EncodeToString([]byte(data)), nil
}

func (de *DataEncryptor) Decrypt(encryptedData string) (string, error) {
    // Implementation would decrypt using AES-GCM
    decoded, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    return string(decoded), nil
}

func (svp *SecureVectorProcessor) ProcessVector(ctx context.Context, vector string, clientID string) (*SecureResult, error) {
    // Rate limiting
    if !svp.rateLimiter.Allow(clientID) {
        svp.auditor.LogSecurityEvent(ctx, "RATE_LIMIT_EXCEEDED", clientID, vector)
        return nil, fmt.Errorf("rate limit exceeded")
    }
    
    // Input validation
    if err := svp.validator.ValidateVector(vector); err != nil {
        svp.auditor.LogSecurityEvent(ctx, "INVALID_INPUT", clientID, vector)
        return nil, fmt.Errorf("validation failed: %w", err)
    }
    
    // Sanitize input
    sanitizedVector := svp.validator.SanitizeVector(vector)
    
    // Process vector
    parser := parser.NewCvss3xParser(sanitizedVector)
    parsedVector, err := parser.Parse()
    if err != nil {
        svp.auditor.LogSecurityEvent(ctx, "PARSE_ERROR", clientID, sanitizedVector)
        return nil, fmt.Errorf("parsing failed: %w", err)
    }
    
    calculator := cvss.NewCalculator(parsedVector)
    score, err := calculator.Calculate()
    if err != nil {
        svp.auditor.LogSecurityEvent(ctx, "CALCULATION_ERROR", clientID, sanitizedVector)
        return nil, fmt.Errorf("calculation failed: %w", err)
    }
    
    // Encrypt sensitive data if needed
    encryptedVector, err := svp.encryptor.Encrypt(sanitizedVector)
    if err != nil {
        return nil, fmt.Errorf("encryption failed: %w", err)
    }
    
    // Log successful processing
    svp.auditor.LogProcessingEvent(ctx, clientID, sanitizedVector, score)
    
    return &SecureResult{
        EncryptedVector: encryptedVector,
        Score:          score,
        Severity:       calculator.GetSeverityRating(score),
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

## Authentication and Authorization

### JWT Authentication

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
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return as.publicKey, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, fmt.Errorf("invalid token")
}

func (as *AuthService) HasPermission(claims *Claims, permission string) bool {
    for _, p := range claims.Permissions {
        if p == permission || p == "admin" {
            return true
        }
    }
    return false
}

// Middleware for HTTP handlers
func (as *AuthService) AuthMiddleware(requiredPermission string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Missing authorization header", http.StatusUnauthorized)
                return
            }
            
            tokenString := strings.TrimPrefix(authHeader, "Bearer ")
            claims, err := as.ValidateToken(tokenString)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
            
            if !as.HasPermission(claims, requiredPermission) {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }
            
            // Add claims to context
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## Audit Logging

### Comprehensive Audit Trail

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
    
    // Extract additional context
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
    
    // Log to structured logger
    al.logger.WithFields(logrus.Fields{
        "audit_event": event,
    }).Warn("Security event detected")
    
    // Store in database
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
        Details:   fmt.Sprintf("Vector processed successfully, score: %.1f", score),
        Severity:  "INFO",
    }
    
    al.logger.WithFields(logrus.Fields{
        "audit_event": event,
    }).Info("Vector processed successfully")
    
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
        al.logger.WithError(err).Error("Failed to store audit event")
    }
}
```

## Secure Communication

### TLS Configuration

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

### Certificate Validation

```go
func ValidateClientCertificate(cert *x509.Certificate, caCert *x509.Certificate) error {
    // Check if certificate is expired
    now := time.Now()
    if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
        return fmt.Errorf("certificate is expired or not yet valid")
    }
    
    // Verify certificate chain
    roots := x509.NewCertPool()
    roots.AddCert(caCert)
    
    opts := x509.VerifyOptions{
        Roots: roots,
    }
    
    _, err := cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("certificate verification failed: %w", err)
    }
    
    return nil
}
```

## Vulnerability Management

### Security Scanning Integration

```go
type SecurityScanner struct {
    vulnerabilityDB *VulnerabilityDB
    alertManager    *AlertManager
}

type VulnerabilityDB struct {
    db *sql.DB
}

func (vs *SecurityScanner) ScanVector(vector string) (*SecurityScanResult, error) {
    // Parse vector to extract components
    parser := parser.NewCvss3xParser(vector)
    parsedVector, err := parser.Parse()
    if err != nil {
        return nil, err
    }
    
    // Check for known vulnerability patterns
    threats := vs.checkKnownThreats(parsedVector)
    
    // Analyze risk level
    riskLevel := vs.assessRiskLevel(parsedVector, threats)
    
    // Generate recommendations
    recommendations := vs.generateRecommendations(parsedVector, threats)
    
    result := &SecurityScanResult{
        Vector:          vector,
        Threats:         threats,
        RiskLevel:       riskLevel,
        Recommendations: recommendations,
        ScanTime:        time.Now(),
    }
    
    // Alert on high-risk findings
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

## Security Testing

### Security Test Suite

```go
func TestSecurityValidation(t *testing.T) {
    validator := NewSecurityValidator()
    
    maliciousInputs := []struct {
        name  string
        input string
    }{
        {"XSS Script", "<script>alert('xss')</script>"},
        {"SQL Injection", "'; DROP TABLE users; --"},
        {"Path Traversal", "../../../etc/passwd"},
        {"Null Byte", "CVSS:3.1\x00/AV:N"},
        {"Command Injection", "CVSS:3.1; rm -rf /"},
        {"Unicode Attack", "CVSS:3.1\u202e/AV:N"},
        {"Overlong Input", strings.Repeat("A", 10000)},
    }
    
    for _, test := range maliciousInputs {
        t.Run(test.name, func(t *testing.T) {
            err := validator.ValidateVector(test.input)
            assert.Error(t, err, "Should reject malicious input: %s", test.input)
        })
    }
}

func TestRateLimiting(t *testing.T) {
    limiter := NewRateLimiter(5, 10) // 5 requests per second, burst of 10
    
    clientID := "test-client"
    
    // Should allow initial burst
    for i := 0; i < 10; i++ {
        assert.True(t, limiter.Allow(clientID), "Should allow request %d", i+1)
    }
    
    // Should reject additional requests
    assert.False(t, limiter.Allow(clientID), "Should reject request after burst")
    
    // Wait and try again
    time.Sleep(200 * time.Millisecond)
    assert.True(t, limiter.Allow(clientID), "Should allow request after wait")
}
```

## Security Monitoring

### Real-time Security Monitoring

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
            sm.eventCounts[eventType] = 0 // Reset counter
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

## Best Practices

### Security Checklist

1. **Input Validation**
   - Validate all inputs against strict patterns
   - Sanitize inputs before processing
   - Implement length limits
   - Check for malicious patterns

2. **Authentication & Authorization**
   - Use strong authentication mechanisms
   - Implement proper authorization checks
   - Use secure token handling
   - Validate permissions for each operation

3. **Data Protection**
   - Encrypt sensitive data at rest and in transit
   - Use secure key management
   - Implement proper data retention policies
   - Sanitize logs and error messages

4. **Monitoring & Logging**
   - Log all security-relevant events
   - Implement real-time monitoring
   - Set up alerting for suspicious activities
   - Maintain audit trails

5. **Network Security**
   - Use TLS for all communications
   - Implement proper certificate validation
   - Configure secure cipher suites
   - Use network segmentation

## Next Steps

After implementing security measures:

- [Monitoring](/examples/monitoring) - Security monitoring integration
- [Risk Assessment](/examples/risk-assessment) - Risk-level analysis
- [Production](/examples/production) - Production hardening checklist

## Related Documentation

- [Error Handling](/api/error-handling) - Secure error handling
- [Performance](/examples/performance) - Performance under load
- [Monitoring](/examples/monitoring) - Security monitoring
