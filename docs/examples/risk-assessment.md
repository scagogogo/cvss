# Risk Assessment

This guide demonstrates comprehensive risk assessment methodologies using CVSS Skills, including vulnerability prioritization, risk scoring, and enterprise risk management frameworks.

## From CVSS Score to Business Risk

A raw CVSS base score is only the starting point. Temporal and environmental metrics refine it, and business context turns it into a prioritized action:

```mermaid
flowchart LR
    Base["Base Score<br/>(technical severity)"] --> Temp["× Temporal<br/>(exploit maturity, fix availability)"]
    Temp --> Env["× Environmental<br/>(asset value, exposure)"]
    Env --> Ctx["+ Business context<br/>(data sensitivity, compliance)"]
    Ctx --> Prio{Priority}
    Prio -->|"≥ 9.0 & exposed"| P1["P1 · patch now"]
    Prio -->|"7–9"| P2["P2 · this sprint"]
    Prio -->|"< 7"| P3["P3 · backlog"]

    classDef p1 fill:#fff1f0,stroke:#ff4d4f,color:#a8071a;
    classDef p2 fill:#fff7e6,stroke:#fa8c16,color:#873800;
    classDef p3 fill:#f6ffed,stroke:#52c41a,color:#135200;
    class P1 p1;
    class P2 p2;
    class P3 p3;
```

## Overview

Risk assessment with CVSS involves:

- Vulnerability impact analysis
- Threat landscape evaluation
- Business context integration
- Risk scoring and prioritization
- Mitigation strategy development
- Compliance and reporting

## Risk Assessment Framework

### Risk Components

```go
type RiskAssessment struct {
    Vulnerability    *Vulnerability    `json:"vulnerability"`
    ThreatContext    *ThreatContext    `json:"threat_context"`
    BusinessImpact   *BusinessImpact   `json:"business_impact"`
    RiskScore        float64           `json:"risk_score"`
    RiskLevel        string            `json:"risk_level"`
    Recommendations  []Recommendation  `json:"recommendations"`
    Timeline         *Timeline         `json:"timeline"`
}

type Vulnerability struct {
    ID              string    `json:"id"`
    CVSSVector      string    `json:"cvss_vector"`
    BaseScore       float64   `json:"base_score"`
    TemporalScore   float64   `json:"temporal_score"`
    EnvironmentalScore float64 `json:"environmental_score"`
    Severity        string    `json:"severity"`
    Description     string    `json:"description"`
    AffectedSystems []string  `json:"affected_systems"`
}

type ThreatContext struct {
    ExploitAvailable    bool      `json:"exploit_available"`
    ExploitMaturity     string    `json:"exploit_maturity"`
    ThreatActors        []string  `json:"threat_actors"`
    AttackComplexity    string    `json:"attack_complexity"`
    ExposureLevel       string    `json:"exposure_level"`
    GeographicRelevance []string  `json:"geographic_relevance"`
}

type BusinessImpact struct {
    CriticalityLevel    string    `json:"criticality_level"`
    DataSensitivity     string    `json:"data_sensitivity"`
    SystemImportance    string    `json:"system_importance"`
    ComplianceImpact    []string  `json:"compliance_impact"`
    FinancialImpact     float64   `json:"financial_impact"`
    ReputationalImpact  string    `json:"reputational_impact"`
}
```

### Risk Calculator

```go
type RiskCalculator struct {
    weights RiskWeights
    config  RiskConfig
}

type RiskWeights struct {
    CVSSBase        float64 `json:"cvss_base"`
    CVSSTemporal    float64 `json:"cvss_temporal"`
    CVSSEnvironmental float64 `json:"cvss_environmental"`
    ThreatContext   float64 `json:"threat_context"`
    BusinessImpact  float64 `json:"business_impact"`
}

type RiskConfig struct {
    Industry        string            `json:"industry"`
    Organization    string            `json:"organization"`
    RiskTolerance   string            `json:"risk_tolerance"`
    ComplianceReqs  []string          `json:"compliance_requirements"`
    CustomFactors   map[string]float64 `json:"custom_factors"`
}

func NewRiskCalculator(config RiskConfig) *RiskCalculator {
    // Default weights for balanced risk assessment
    weights := RiskWeights{
        CVSSBase:          0.4,
        CVSSTemporal:      0.2,
        CVSSEnvironmental: 0.2,
        ThreatContext:     0.1,
        BusinessImpact:    0.1,
    }
    
    // Adjust weights based on industry
    switch config.Industry {
    case "financial":
        weights.BusinessImpact = 0.25
        weights.CVSSEnvironmental = 0.25
    case "healthcare":
        weights.BusinessImpact = 0.3
        weights.CVSSBase = 0.3
    case "government":
        weights.ThreatContext = 0.2
        weights.CVSSEnvironmental = 0.3
    }
    
    return &RiskCalculator{
        weights: weights,
        config:  config,
    }
}

func (rc *RiskCalculator) CalculateRisk(vuln *Vulnerability, threat *ThreatContext, business *BusinessImpact) *RiskAssessment {
    // Calculate weighted risk score
    riskScore := rc.calculateWeightedScore(vuln, threat, business)
    
    // Determine risk level
    riskLevel := rc.determineRiskLevel(riskScore)
    
    // Generate recommendations
    recommendations := rc.generateRecommendations(vuln, threat, business, riskScore)
    
    // Create timeline
    timeline := rc.createTimeline(riskLevel, vuln.Severity)
    
    return &RiskAssessment{
        Vulnerability:   vuln,
        ThreatContext:   threat,
        BusinessImpact:  business,
        RiskScore:       riskScore,
        RiskLevel:       riskLevel,
        Recommendations: recommendations,
        Timeline:        timeline,
    }
}

func (rc *RiskCalculator) calculateWeightedScore(vuln *Vulnerability, threat *ThreatContext, business *BusinessImpact) float64 {
    score := 0.0
    
    // CVSS Base Score component
    score += vuln.BaseScore * rc.weights.CVSSBase
    
    // CVSS Temporal Score component
    if vuln.TemporalScore > 0 {
        score += vuln.TemporalScore * rc.weights.CVSSTemporal
    } else {
        score += vuln.BaseScore * rc.weights.CVSSTemporal
    }
    
    // CVSS Environmental Score component
    if vuln.EnvironmentalScore > 0 {
        score += vuln.EnvironmentalScore * rc.weights.CVSSEnvironmental
    } else {
        score += vuln.BaseScore * rc.weights.CVSSEnvironmental
    }
    
    // Threat Context component
    threatScore := rc.calculateThreatScore(threat)
    score += threatScore * rc.weights.ThreatContext
    
    // Business Impact component
    businessScore := rc.calculateBusinessScore(business)
    score += businessScore * rc.weights.BusinessImpact
    
    // Normalize to 0-10 scale
    return math.Min(score, 10.0)
}
```

## Vulnerability Prioritization

### Priority Matrix

```go
type VulnerabilityPriority struct {
    Vulnerability *Vulnerability `json:"vulnerability"`
    Priority      int           `json:"priority"`
    Urgency       string        `json:"urgency"`
    Impact        string        `json:"impact"`
    Effort        string        `json:"effort"`
    ROI           float64       `json:"roi"`
}

func PrioritizeVulnerabilities(vulnerabilities []*Vulnerability, context *OrganizationContext) []*VulnerabilityPriority {
    priorities := make([]*VulnerabilityPriority, len(vulnerabilities))
    
    for i, vuln := range vulnerabilities {
        priority := &VulnerabilityPriority{
            Vulnerability: vuln,
            Urgency:       calculateUrgency(vuln),
            Impact:        calculateImpact(vuln, context),
            Effort:        estimateEffort(vuln, context),
        }
        
        priority.Priority = calculatePriorityScore(priority)
        priority.ROI = calculateROI(priority)
        priorities[i] = priority
    }
    
    // Sort by priority (highest first)
    sort.Slice(priorities, func(i, j int) bool {
        return priorities[i].Priority > priorities[j].Priority
    })
    
    return priorities
}

func calculateUrgency(vuln *Vulnerability) string {
    if vuln.BaseScore >= 9.0 {
        return "Critical"
    } else if vuln.BaseScore >= 7.0 {
        return "High"
    } else if vuln.BaseScore >= 4.0 {
        return "Medium"
    }
    return "Low"
}

func calculateImpact(vuln *Vulnerability, context *OrganizationContext) string {
    impactScore := 0
    
    // Check if vulnerability affects critical systems
    for _, system := range vuln.AffectedSystems {
        if contains(context.CriticalSystems, system) {
            impactScore += 3
        } else if contains(context.ImportantSystems, system) {
            impactScore += 2
        } else {
            impactScore += 1
        }
    }
    
    // Consider data sensitivity
    if vuln.BaseScore >= 7.0 && impactScore >= 3 {
        return "Critical"
    } else if vuln.BaseScore >= 4.0 && impactScore >= 2 {
        return "High"
    } else if impactScore >= 1 {
        return "Medium"
    }
    return "Low"
}
```

## Risk Reporting

### Executive Dashboard

```go
type RiskDashboard struct {
    Summary          *RiskSummary          `json:"summary"`
    TrendAnalysis    *TrendAnalysis        `json:"trend_analysis"`
    TopRisks         []*RiskAssessment     `json:"top_risks"`
    ComplianceStatus *ComplianceStatus     `json:"compliance_status"`
    Recommendations  []*ActionItem         `json:"recommendations"`
    Metrics          *RiskMetrics          `json:"metrics"`
}

type RiskSummary struct {
    TotalVulnerabilities int                    `json:"total_vulnerabilities"`
    RiskDistribution     map[string]int         `json:"risk_distribution"`
    AverageRiskScore     float64                `json:"average_risk_score"`
    TrendDirection       string                 `json:"trend_direction"`
    LastUpdated          time.Time              `json:"last_updated"`
}

type TrendAnalysis struct {
    TimeRange        string                     `json:"time_range"`
    RiskTrend        []RiskDataPoint           `json:"risk_trend"`
    VulnerabilityTrend []VulnerabilityDataPoint `json:"vulnerability_trend"`
    Predictions      *RiskPrediction           `json:"predictions"`
}

type RiskDataPoint struct {
    Date      time.Time `json:"date"`
    RiskScore float64   `json:"risk_score"`
    Count     int       `json:"count"`
}

func GenerateRiskDashboard(assessments []*RiskAssessment, timeRange string) *RiskDashboard {
    dashboard := &RiskDashboard{
        Summary:          generateRiskSummary(assessments),
        TrendAnalysis:    analyzeTrends(assessments, timeRange),
        TopRisks:         getTopRisks(assessments, 10),
        ComplianceStatus: assessCompliance(assessments),
        Recommendations:  generateActionItems(assessments),
        Metrics:          calculateRiskMetrics(assessments),
    }
    
    return dashboard
}

func generateRiskSummary(assessments []*RiskAssessment) *RiskSummary {
    distribution := make(map[string]int)
    totalScore := 0.0
    
    for _, assessment := range assessments {
        distribution[assessment.RiskLevel]++
        totalScore += assessment.RiskScore
    }
    
    avgScore := totalScore / float64(len(assessments))
    
    return &RiskSummary{
        TotalVulnerabilities: len(assessments),
        RiskDistribution:     distribution,
        AverageRiskScore:     avgScore,
        TrendDirection:       calculateTrendDirection(assessments),
        LastUpdated:          time.Now(),
    }
}
```

## Industry-Specific Risk Assessment

### Financial Services

```go
func AssessFinancialRisk(vuln *Vulnerability) *FinancialRiskAssessment {
    assessment := &FinancialRiskAssessment{
        BaseAssessment: calculateBaseRisk(vuln),
    }
    
    // Financial-specific factors
    if affectsPaymentSystems(vuln) {
        assessment.RegulatoryImpact = "High"
        assessment.FinancialLoss = estimateFinancialLoss(vuln, "payment")
    }
    
    if affectsCustomerData(vuln) {
        assessment.ComplianceRisk = []string{"PCI-DSS", "SOX", "GDPR"}
        assessment.ReputationalRisk = "Critical"
    }
    
    // Calculate adjusted risk score
    assessment.AdjustedRiskScore = applyFinancialWeights(assessment)
    
    return assessment
}

type FinancialRiskAssessment struct {
    BaseAssessment     *RiskAssessment `json:"base_assessment"`
    RegulatoryImpact   string          `json:"regulatory_impact"`
    ComplianceRisk     []string        `json:"compliance_risk"`
    FinancialLoss      float64         `json:"financial_loss"`
    ReputationalRisk   string          `json:"reputational_risk"`
    AdjustedRiskScore  float64         `json:"adjusted_risk_score"`
}
```

### Healthcare

```go
func AssessHealthcareRisk(vuln *Vulnerability) *HealthcareRiskAssessment {
    assessment := &HealthcareRiskAssessment{
        BaseAssessment: calculateBaseRisk(vuln),
    }
    
    // Healthcare-specific factors
    if affectsPatientData(vuln) {
        assessment.HIPAAImpact = "Critical"
        assessment.PatientSafety = assessPatientSafetyRisk(vuln)
    }
    
    if affectsMedicalDevices(vuln) {
        assessment.FDACompliance = "Required"
        assessment.ClinicalImpact = "High"
    }
    
    // Calculate adjusted risk score
    assessment.AdjustedRiskScore = applyHealthcareWeights(assessment)
    
    return assessment
}

type HealthcareRiskAssessment struct {
    BaseAssessment     *RiskAssessment `json:"base_assessment"`
    HIPAAImpact        string          `json:"hipaa_impact"`
    PatientSafety      string          `json:"patient_safety"`
    FDACompliance      string          `json:"fda_compliance"`
    ClinicalImpact     string          `json:"clinical_impact"`
    AdjustedRiskScore  float64         `json:"adjusted_risk_score"`
}
```

## Risk Mitigation Strategies

### Mitigation Planning

```go
type MitigationPlan struct {
    VulnerabilityID   string              `json:"vulnerability_id"`
    RiskLevel         string              `json:"risk_level"`
    Strategies        []MitigationStrategy `json:"strategies"`
    Timeline          *MitigationTimeline `json:"timeline"`
    Resources         *ResourceRequirements `json:"resources"`
    Success           *SuccessMetrics     `json:"success_metrics"`
}

type MitigationStrategy struct {
    Type          string    `json:"type"`
    Description   string    `json:"description"`
    Effectiveness float64   `json:"effectiveness"`
    Cost          float64   `json:"cost"`
    Complexity    string    `json:"complexity"`
    Dependencies  []string  `json:"dependencies"`
}

func GenerateMitigationPlan(assessment *RiskAssessment) *MitigationPlan {
    strategies := []MitigationStrategy{}
    
    // Patch management
    if isPatchable(assessment.Vulnerability) {
        strategies = append(strategies, MitigationStrategy{
            Type:          "Patch",
            Description:   "Apply vendor security patch",
            Effectiveness: 0.95,
            Cost:          calculatePatchCost(assessment.Vulnerability),
            Complexity:    "Low",
            Dependencies:  []string{"Change Management", "Testing"},
        })
    }
    
    // Configuration changes
    if hasConfigFix(assessment.Vulnerability) {
        strategies = append(strategies, MitigationStrategy{
            Type:          "Configuration",
            Description:   "Implement secure configuration",
            Effectiveness: 0.8,
            Cost:          100,
            Complexity:    "Medium",
            Dependencies:  []string{"System Administration"},
        })
    }
    
    // Compensating controls
    strategies = append(strategies, generateCompensatingControls(assessment)...)
    
    return &MitigationPlan{
        VulnerabilityID: assessment.Vulnerability.ID,
        RiskLevel:       assessment.RiskLevel,
        Strategies:      strategies,
        Timeline:        createMitigationTimeline(assessment.RiskLevel),
        Resources:       calculateResourceRequirements(strategies),
        Success:         defineSucessMetrics(assessment),
    }
}
```

## Compliance Integration

### Regulatory Mapping

```go
type ComplianceMapping struct {
    Framework     string            `json:"framework"`
    Requirements  []string          `json:"requirements"`
    Controls      []string          `json:"controls"`
    RiskLevel     string            `json:"risk_level"`
    Gaps          []ComplianceGap   `json:"gaps"`
}

type ComplianceGap struct {
    Requirement string `json:"requirement"`
    Current     string `json:"current_state"`
    Required    string `json:"required_state"`
    Gap         string `json:"gap_description"`
    Priority    string `json:"priority"`
}

func MapToCompliance(assessment *RiskAssessment, frameworks []string) []ComplianceMapping {
    mappings := []ComplianceMapping{}
    
    for _, framework := range frameworks {
        mapping := ComplianceMapping{
            Framework: framework,
        }
        
        switch framework {
        case "NIST":
            mapping = mapToNIST(assessment)
        case "ISO27001":
            mapping = mapToISO27001(assessment)
        case "PCI-DSS":
            mapping = mapToPCIDSS(assessment)
        case "SOC2":
            mapping = mapToSOC2(assessment)
        }
        
        mappings = append(mappings, mapping)
    }
    
    return mappings
}
```

## Testing and Validation

### Risk Assessment Testing

```go
func TestRiskAssessment(t *testing.T) {
    testCases := []struct {
        name           string
        vulnerability  *Vulnerability
        expectedRisk   string
        expectedScore  float64
    }{
        {
            name: "Critical vulnerability in production",
            vulnerability: &Vulnerability{
                CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                BaseScore:  9.8,
                AffectedSystems: []string{"production-web", "database"},
            },
            expectedRisk:  "Critical",
            expectedScore: 9.5,
        },
        {
            name: "Medium vulnerability in development",
            vulnerability: &Vulnerability{
                CVSSVector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                BaseScore:  3.8,
                AffectedSystems: []string{"dev-environment"},
            },
            expectedRisk:  "Low",
            expectedScore: 2.5,
        },
    }
    
    calculator := NewRiskCalculator(RiskConfig{
        Industry: "technology",
        RiskTolerance: "medium",
    })
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            threat := &ThreatContext{
                ExploitAvailable: true,
                ExploitMaturity:  "Functional",
            }
            
            business := &BusinessImpact{
                CriticalityLevel: "High",
                DataSensitivity:  "Confidential",
            }
            
            assessment := calculator.CalculateRisk(tc.vulnerability, threat, business)
            
            assert.Equal(t, tc.expectedRisk, assessment.RiskLevel)
            assert.InDelta(t, tc.expectedScore, assessment.RiskScore, 0.5)
        })
    }
}
```

## Next Steps

After implementing risk assessment, explore:

- [Risk Management](/examples/risk-assessment) - Ongoing risk management processes
- [Compliance Automation](/examples/security) - Automated compliance reporting
- [Security Metrics](/examples/monitoring) - Advanced security measurements

## Related Documentation

- [Severity Classification](/examples/severity) - Understanding CVSS severity
- [Environmental Metrics](/examples/environmental) - Environmental score calculation
- [Temporal Metrics](/examples/temporal) - Temporal score analysis
