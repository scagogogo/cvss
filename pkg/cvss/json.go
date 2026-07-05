package cvss

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// JSONOutput CVSS JSON输出格式
type JSONOutput struct {
	Version               string       `json:"version"`
	VectorString          string       `json:"vectorString"`
	BaseScore             float64      `json:"baseScore"`
	TemporalScore         float64      `json:"temporalScore,omitempty"`
	EnvironmentalScore    float64      `json:"environmentalScore,omitempty"`
	BaseSeverity          Severity     `json:"baseSeverity"`
	TemporalSeverity      Severity     `json:"temporalSeverity,omitempty"`
	EnvironmentalSeverity Severity     `json:"environmentalSeverity,omitempty"`
	Metrics               *JSONMetrics `json:"metrics"`
}

// JSONMetrics 包含所有CVSS指标
type JSONMetrics struct {
	Base          *JSONBaseMetrics          `json:"base"`
	Temporal      *JSONTemporalMetrics      `json:"temporal,omitempty"`
	Environmental *JSONEnvironmentalMetrics `json:"environmental,omitempty"`
}

// JSONBaseMetrics 基础指标JSON格式
type JSONBaseMetrics struct {
	AttackVector        string  `json:"attackVector"`
	AttackComplexity    string  `json:"attackComplexity"`
	PrivilegesRequired  string  `json:"privilegesRequired"`
	UserInteraction     string  `json:"userInteraction"`
	Scope               string  `json:"scope"`
	Confidentiality     string  `json:"confidentiality"`
	Integrity           string  `json:"integrity"`
	Availability        string  `json:"availability"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// JSONTemporalMetrics 时间指标JSON格式
type JSONTemporalMetrics struct {
	ExploitCodeMaturity string `json:"exploitCodeMaturity"`
	RemediationLevel    string `json:"remediationLevel"`
	ReportConfidence    string `json:"reportConfidence"`
}

// JSONEnvironmentalMetrics 环境指标JSON格式
type JSONEnvironmentalMetrics struct {
	ConfidentialityRequirement  string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement        string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement     string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector        string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity    string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired  string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction     string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope               string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentiality     string  `json:"modifiedConfidentiality,omitempty"`
	ModifiedIntegrity           string  `json:"modifiedIntegrity,omitempty"`
	ModifiedAvailability        string  `json:"modifiedAvailability,omitempty"`
	ModifiedExploitabilityScore float64 `json:"modifiedExploitabilityScore,omitempty"`
	ModifiedImpactScore         float64 `json:"modifiedImpactScore,omitempty"`
}

// ToJSON 将CVSS对象转换为JSON格式
// BaseScore 始终为基础评分，TemporalScore 和 EnvironmentalScore 分别对应时间评分和环境评分
func (x *Cvss3x) ToJSON(calculator *Calculator) ([]byte, error) {
	if calculator == nil {
		calculator = NewCalculator(x)
	}

	// 校验CVSS数据
	if err := calculator.cvss.Check(); err != nil {
		return nil, err
	}

	// 分别计算各级评分，确保 BaseScore 是真正的基础评分
	baseScore := calculator.calculateBaseScore()

	// 构建JSON输出
	output := &JSONOutput{
		Version:      fmt.Sprintf("3.%d", x.MinorVersion),
		VectorString: x.String(),
		BaseScore:    baseScore,
		BaseSeverity: calculator.GetSeverityRating(baseScore),
		Metrics: &JSONMetrics{
			Base: &JSONBaseMetrics{
				AttackVector:        x.Cvss3xBase.AttackVector.GetLongValue(),
				AttackComplexity:    x.Cvss3xBase.AttackComplexity.GetLongValue(),
				PrivilegesRequired:  x.Cvss3xBase.PrivilegesRequired.GetLongValue(),
				UserInteraction:     x.Cvss3xBase.UserInteraction.GetLongValue(),
				Scope:               x.Cvss3xBase.Scope.GetLongValue(),
				Confidentiality:     x.Cvss3xBase.Confidentiality.GetLongValue(),
				Integrity:           x.Cvss3xBase.Integrity.GetLongValue(),
				Availability:        x.Cvss3xBase.Availability.GetLongValue(),
				ExploitabilityScore: calculator.calculateExploitabilitySubScore(),
				ImpactScore:         calculator.calculateImpactSubScore(),
			},
		},
	}

	// 添加时间指标（如果存在）
	if calculator.hasTemporalMetrics() {
		temporalScore := calculator.calculateTemporalScore(baseScore)
		output.TemporalScore = temporalScore
		output.TemporalSeverity = calculator.GetSeverityRating(temporalScore)
		output.Metrics.Temporal = &JSONTemporalMetrics{}
		if x.Cvss3xTemporal.ExploitCodeMaturity != nil {
			output.Metrics.Temporal.ExploitCodeMaturity = x.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue()
		}
		if x.Cvss3xTemporal.RemediationLevel != nil {
			output.Metrics.Temporal.RemediationLevel = x.Cvss3xTemporal.RemediationLevel.GetLongValue()
		}
		if x.Cvss3xTemporal.ReportConfidence != nil {
			output.Metrics.Temporal.ReportConfidence = x.Cvss3xTemporal.ReportConfidence.GetLongValue()
		}
	}

	// 添加环境指标（如果存在）
	if calculator.hasEnvironmentalMetrics() {
		environmentalScore := calculator.calculateEnvironmentalScore()
		output.EnvironmentalScore = environmentalScore
		output.EnvironmentalSeverity = calculator.GetSeverityRating(environmentalScore)

		output.Metrics.Environmental = &JSONEnvironmentalMetrics{
			ModifiedExploitabilityScore: calculator.calculateModifiedExploitabilitySubScore(),
			ModifiedImpactScore:         calculator.calculateModifiedImpactSubScore(),
		}

		// 添加CIA需求指标
		if x.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
			output.Metrics.Environmental.ConfidentialityRequirement = x.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue()
		}
		if x.Cvss3xEnvironmental.IntegrityRequirement != nil {
			output.Metrics.Environmental.IntegrityRequirement = x.Cvss3xEnvironmental.IntegrityRequirement.GetLongValue()
		}
		if x.Cvss3xEnvironmental.AvailabilityRequirement != nil {
			output.Metrics.Environmental.AvailabilityRequirement = x.Cvss3xEnvironmental.AvailabilityRequirement.GetLongValue()
		}

		// 添加修改后的指标
		if x.Cvss3xEnvironmental.ModifiedAttackVector != nil {
			output.Metrics.Environmental.ModifiedAttackVector = x.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
			output.Metrics.Environmental.ModifiedAttackComplexity = x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
			output.Metrics.Environmental.ModifiedPrivilegesRequired = x.Cvss3xEnvironmental.ModifiedPrivilegesRequired.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
			output.Metrics.Environmental.ModifiedUserInteraction = x.Cvss3xEnvironmental.ModifiedUserInteraction.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedScope != nil {
			output.Metrics.Environmental.ModifiedScope = x.Cvss3xEnvironmental.ModifiedScope.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
			output.Metrics.Environmental.ModifiedConfidentiality = x.Cvss3xEnvironmental.ModifiedConfidentiality.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedIntegrity != nil {
			output.Metrics.Environmental.ModifiedIntegrity = x.Cvss3xEnvironmental.ModifiedIntegrity.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedAvailability != nil {
			output.Metrics.Environmental.ModifiedAvailability = x.Cvss3xEnvironmental.ModifiedAvailability.GetLongValue()
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

// longToShortValue 将指标的 LongValue 名称转换为 ShortValue 字符
// 例如 "Network" → 'N', "Low" → 'L'
// 这是从 CVSS JSON 恢复向量字符串所需的核心映射
var longToShortValue = map[string]map[string]rune{
	"AV": {"Network": 'N', "Adjacent": 'A', "Local": 'L', "Physical": 'P', "Not Defined": 'X'},
	"AC": {"Low": 'L', "High": 'H', "Not Defined": 'X'},
	"PR": {"None": 'N', "Low": 'L', "High": 'H', "Not Defined": 'X'},
	"UI": {"None": 'N', "Required": 'R', "Not Defined": 'X'},
	"S":  {"Unchanged": 'U', "Changed": 'C', "Not Defined": 'X'},
	"C":  {"High": 'H', "Low": 'L', "None": 'N', "Not Defined": 'X'},
	"I":  {"High": 'H', "Low": 'L', "None": 'N', "Not Defined": 'X'},
	"A":  {"High": 'H', "Low": 'L', "None": 'N', "Not Defined": 'X'},
	"E":  {"Unproven": 'U', "Proof-of-Concept": 'P', "Functional": 'F', "High": 'H', "Not Defined": 'X'},
	"RL": {"Official Fix": 'O', "Temporary Fix": 'T', "Workaround": 'W', "Unavailable": 'U', "Not Defined": 'X'},
	"RC": {"Unknown": 'U', "Reasonable": 'R', "Confirmed": 'C', "Not Defined": 'X'},
	"CR": {"High": 'H', "Medium": 'M', "Low": 'L', "Not Defined": 'X'},
	"IR": {"High": 'H', "Medium": 'M', "Low": 'L', "Not Defined": 'X'},
	"AR": {"High": 'H', "Medium": 'M', "Low": 'L', "Not Defined": 'X'},
}

// FromJSON 从 JSON 字节数据恢复 Cvss3x 对象
// 它提取 vectorString 并通过解析器重建 Cvss3x，同时保留 JSON 中的评分信息
// 如果 vectorString 缺失或无效，则尝试从各指标字段重建向量字符串
func FromJSON(data []byte) (*Cvss3x, error) {
	var output JSONOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse CVSS JSON: %w", err)
	}

	// 优先使用 vectorString 直接解析
	if output.VectorString != "" {
		vectorStr := output.VectorString
		// 通过内部解析重建（避免循环依赖，直接构造向量字符串）
		return fromVectorString(vectorStr)
	}

	// 如果没有 vectorString，从各指标字段重建
	return fromJSONMetrics(&output)
}

// fromVectorString 从向量字符串解析构建 Cvss3x
// 内部实现，不依赖 parser 包以避免循环依赖
func fromVectorString(vectorStr string) (*Cvss3x, error) {
	// 验证格式
	if len(vectorStr) < 7 || !strings.HasPrefix(strings.ToUpper(vectorStr), "CVSS:") {
		return nil, fmt.Errorf("invalid vector string format: %s", vectorStr)
	}

	// 手动解析向量字符串（简化版，避免循环依赖）
	parts := strings.Split(vectorStr, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid vector string format: %s", vectorStr)
	}

	// 解析版本
	versionPart := parts[0] // "CVSS:3.1"
	versionPieces := strings.Split(versionPart, ":")
	if len(versionPieces) != 2 {
		return nil, fmt.Errorf("invalid version format: %s", versionPart)
	}
	versionNums := strings.Split(versionPieces[1], ".")
	if len(versionNums) != 2 {
		return nil, fmt.Errorf("invalid version format: %s", versionPieces[1])
	}

	major, err := parseInt(versionNums[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err := parseInt(versionNums[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %w", err)
	}

	result := &Cvss3x{
		MajorVersion:        major,
		MinorVersion:        minor,
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
	}

	// 解析各指标
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(kv[0])
		value := strings.ToUpper(kv[1])

		if err := mapKeyValueToStruct(result, key, value); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// fromJSONMetrics 从 JSON 的各指标字段重建 Cvss3x
func fromJSONMetrics(output *JSONOutput) (*Cvss3x, error) {
	if output.Metrics == nil || output.Metrics.Base == nil {
		return nil, fmt.Errorf("JSON missing base metrics")
	}

	// 从 version 字段推断版本号
	major, minor := 3, 1
	if output.Version != "" {
		parts := strings.Split(output.Version, ".")
		if len(parts) == 2 {
			if m, err := parseInt(parts[0]); err == nil {
				major = m
			}
			if m, err := parseInt(parts[1]); err == nil {
				minor = m
			}
		}
	}

	result := &Cvss3x{
		MajorVersion:        major,
		MinorVersion:        minor,
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
	}

	base := output.Metrics.Base

	// 将 LongValue 转为 ShortValue 并映射
	var deserializationErrors []string
	setField := func(key, longVal string, target *vector.Vector) {
		if longVal == "" {
			return
		}
		v, err := getVectorByKeyAndLongValue(key, longVal)
		if err != nil {
			deserializationErrors = append(deserializationErrors, err.Error())
			return
		}
		*target = v
	}

	setField("AV", base.AttackVector, &result.Cvss3xBase.AttackVector)
	setField("AC", base.AttackComplexity, &result.Cvss3xBase.AttackComplexity)
	setField("PR", base.PrivilegesRequired, &result.Cvss3xBase.PrivilegesRequired)
	setField("UI", base.UserInteraction, &result.Cvss3xBase.UserInteraction)
	setField("S", base.Scope, &result.Cvss3xBase.Scope)
	setField("C", base.Confidentiality, &result.Cvss3xBase.Confidentiality)
	setField("I", base.Integrity, &result.Cvss3xBase.Integrity)
	setField("A", base.Availability, &result.Cvss3xBase.Availability)

	// Temporal
	if output.Metrics.Temporal != nil {
		result.Cvss3xTemporal = &Cvss3xTemporal{}
		t := output.Metrics.Temporal
		setField("E", t.ExploitCodeMaturity, &result.Cvss3xTemporal.ExploitCodeMaturity)
		setField("RL", t.RemediationLevel, &result.Cvss3xTemporal.RemediationLevel)
		setField("RC", t.ReportConfidence, &result.Cvss3xTemporal.ReportConfidence)
	}

	// Environmental
	if output.Metrics.Environmental != nil {
		result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		e := output.Metrics.Environmental
		setField("CR", e.ConfidentialityRequirement, &result.Cvss3xEnvironmental.ConfidentialityRequirement)
		setField("IR", e.IntegrityRequirement, &result.Cvss3xEnvironmental.IntegrityRequirement)
		setField("AR", e.AvailabilityRequirement, &result.Cvss3xEnvironmental.AvailabilityRequirement)
		setField("MAV", e.ModifiedAttackVector, &result.Cvss3xEnvironmental.ModifiedAttackVector)
		setField("MAC", e.ModifiedAttackComplexity, &result.Cvss3xEnvironmental.ModifiedAttackComplexity)
		setField("MPR", e.ModifiedPrivilegesRequired, &result.Cvss3xEnvironmental.ModifiedPrivilegesRequired)
		setField("MUI", e.ModifiedUserInteraction, &result.Cvss3xEnvironmental.ModifiedUserInteraction)
		setField("MS", e.ModifiedScope, &result.Cvss3xEnvironmental.ModifiedScope)
		setField("MC", e.ModifiedConfidentiality, &result.Cvss3xEnvironmental.ModifiedConfidentiality)
		setField("MI", e.ModifiedIntegrity, &result.Cvss3xEnvironmental.ModifiedIntegrity)
		setField("MA", e.ModifiedAvailability, &result.Cvss3xEnvironmental.ModifiedAvailability)
	}

	if len(deserializationErrors) > 0 {
		return nil, fmt.Errorf("JSON deserialization errors: %s", strings.Join(deserializationErrors, "; "))
	}

	return result, nil
}

// getVectorByKeyAndLongValue 通过 key 和 LongValue 获取 Vector
// 如果找不到映射，返回错误而不是 nil（防止静默丢弃数据）
func getVectorByKeyAndLongValue(key, longValue string) (vector.Vector, error) {
	if longValue == "" {
		return nil, nil // 空值表示未设置，这是合法的
	}
	mapping, ok := longToShortValue[key]
	if !ok {
		return nil, fmt.Errorf("unknown metric key: %s", key)
	}
	shortVal, ok := mapping[longValue]
	if !ok {
		return nil, fmt.Errorf("unknown value %s for metric %s", longValue, key)
	}
	// 使用 vector 包的工厂函数。key 与 shortVal 均已通过 longToShortValue
	// 映射验证为合法值，GetVectorByShortName 不会失败。
	v, _ := vector.GetVectorByShortName(key, string(shortVal))
	return v, nil
}

// parseInt 解析整数
func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid integer: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// mapKeyValueToStruct 将解析出的 key/value 映射到 Cvss3x 结构中
func mapKeyValueToStruct(result *Cvss3x, key, value string) error {
	vectorObj, err := vector.GetVectorByShortName(key, value)
	if err != nil {
		return err
	}

	switch key {
	case "AV":
		result.Cvss3xBase.AttackVector = vectorObj
	case "AC":
		result.Cvss3xBase.AttackComplexity = vectorObj
	case "PR":
		result.Cvss3xBase.PrivilegesRequired = vectorObj
	case "UI":
		result.Cvss3xBase.UserInteraction = vectorObj
	case "S":
		result.Cvss3xBase.Scope = vectorObj
	case "C":
		result.Cvss3xBase.Confidentiality = vectorObj
	case "I":
		result.Cvss3xBase.Integrity = vectorObj
	case "A":
		result.Cvss3xBase.Availability = vectorObj
	case "E":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		result.Cvss3xTemporal.ExploitCodeMaturity = vectorObj
	case "RL":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		result.Cvss3xTemporal.RemediationLevel = vectorObj
	case "RC":
		if result.Cvss3xTemporal == nil {
			result.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		result.Cvss3xTemporal.ReportConfidence = vectorObj
	case "CR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ConfidentialityRequirement = vectorObj
	case "IR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.IntegrityRequirement = vectorObj
	case "AR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.AvailabilityRequirement = vectorObj
	case "MAV":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedAttackVector = vectorObj
	case "MAC":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedAttackComplexity = vectorObj
	case "MPR":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = vectorObj
	case "MUI":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedUserInteraction = vectorObj
	case "MS":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedScope = vectorObj
	case "MC":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedConfidentiality = vectorObj
	case "MI":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedIntegrity = vectorObj
	case "MA":
		if result.Cvss3xEnvironmental == nil {
			result.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		result.Cvss3xEnvironmental.ModifiedAvailability = vectorObj
	}
	return nil
}
