package mock

import (
	"fmt"
	"math/rand"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// RandomCvss3x 生成一个随机的 CVSS 3.x 对象（仅包含基础指标）
// minorVersion 指定次版本号（0 或 1）
func RandomCvss3x(minorVersion int) *cvss.Cvss3x {
	if minorVersion != 0 && minorVersion != 1 {
		minorVersion = 1
	}

	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = minorVersion

	// 随机基础指标
	result.Cvss3xBase.AttackVector = randomFromSlice([]vector.Vector{
		vector.AttackVectorNetwork, vector.AttackVectorAdjacent,
		vector.AttackVectorLocal, vector.AttackVectorPhysical,
	})
	result.Cvss3xBase.AttackComplexity = randomFromSlice([]vector.Vector{
		vector.AttackComplexityLow, vector.AttackComplexityHigh,
	})
	result.Cvss3xBase.PrivilegesRequired = randomFromSlice([]vector.Vector{
		vector.PrivilegesRequiredNone, vector.PrivilegesRequiredLow,
		vector.PrivilegesRequiredHigh,
	})
	result.Cvss3xBase.UserInteraction = randomFromSlice([]vector.Vector{
		vector.UserInteractionNone, vector.UserInteractionRequired,
	})
	result.Cvss3xBase.Scope = randomFromSlice([]vector.Vector{
		vector.ScopeUnchanged, vector.ScopeChanged,
	})
	result.Cvss3xBase.Confidentiality = randomFromSlice([]vector.Vector{
		vector.ConfidentialityHigh, vector.ConfidentialityLow, vector.ConfidentialityNone,
	})
	result.Cvss3xBase.Integrity = randomFromSlice([]vector.Vector{
		vector.IntegrityHigh, vector.IntegrityLow, vector.IntegrityNone,
	})
	result.Cvss3xBase.Availability = randomFromSlice([]vector.Vector{
		vector.AvailabilityHigh, vector.AvailabilityLow, vector.AvailabilityNone,
	})

	return result
}

// RandomCvss3xWithTemporal 生成一个随机的 CVSS 3.x 对象（包含基础和时间指标）
func RandomCvss3xWithTemporal(minorVersion int) *cvss.Cvss3x {
	result := RandomCvss3x(minorVersion)

	result.Cvss3xTemporal = &cvss.Cvss3xTemporal{}
	result.Cvss3xTemporal.ExploitCodeMaturity = randomFromSlice([]vector.Vector{
		vector.ExploitCodeMaturityNotDefined, vector.ExploitCodeMaturityUnproven,
		vector.ExploitCodeMaturityProofOfConcept, vector.ExploitCodeMaturityFunctional,
		vector.ExploitCodeMaturityHigh,
	})
	result.Cvss3xTemporal.RemediationLevel = randomFromSlice([]vector.Vector{
		vector.RemediationLevelNotDefined, vector.RemediationLevelOfficialFix,
		vector.RemediationLevelTemporaryFix, vector.RemediationLevelWorkaround,
		vector.RemediationLevelUnavailable,
	})
	result.Cvss3xTemporal.ReportConfidence = randomFromSlice([]vector.Vector{
		vector.ReportConfidenceNotDefined, vector.ReportConfidenceUnknown,
		vector.ReportConfidenceReasonable, vector.ReportConfidenceConfirmed,
	})

	return result
}

// RandomCvss3xFull 生成一个随机的 CVSS 3.x 对象（包含所有指标）
func RandomCvss3xFull(minorVersion int) *cvss.Cvss3x {
	result := RandomCvss3xWithTemporal(minorVersion)

	// CIA Requirements
	result.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
	result.Cvss3xEnvironmental.ConfidentialityRequirement = randomFromSlice([]vector.Vector{
		vector.ConfidentialityRequirementNotDefined, vector.ConfidentialityRequirementLow,
		vector.ConfidentialityRequirementMedium, vector.ConfidentialityRequirementHigh,
	})
	result.Cvss3xEnvironmental.IntegrityRequirement = randomFromSlice([]vector.Vector{
		vector.IntegrityRequirementNotDefined, vector.IntegrityRequirementLow,
		vector.IntegrityRequirementMedium, vector.IntegrityRequirementHigh,
	})
	result.Cvss3xEnvironmental.AvailabilityRequirement = randomFromSlice([]vector.Vector{
		vector.AvailabilityRequirementNotDefined, vector.AvailabilityRequirementLow,
		vector.AvailabilityRequirementMedium, vector.AvailabilityRequirementHigh,
	})

	// Modified Base Metrics
	result.Cvss3xEnvironmental.ModifiedAttackVector = randomFromSlice([]vector.Vector{
		vector.AttackVectorNotDefined, vector.ModifiedAttackVectorNetwork,
		vector.ModifiedAttackVectorAdjacent, vector.ModifiedAttackVectorLocal,
		vector.ModifiedAttackVectorPhysical,
	})
	result.Cvss3xEnvironmental.ModifiedAttackComplexity = randomFromSlice([]vector.Vector{
		vector.AttackComplexityNotDefined, vector.ModifiedAttackComplexityLow,
		vector.ModifiedAttackComplexityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = randomFromSlice([]vector.Vector{
		vector.PrivilegesRequiredNotDefined, vector.ModifiedPrivilegesRequiredNone,
		vector.ModifiedPrivilegesRequiredLow, vector.ModifiedPrivilegesRequiredHigh,
	})
	result.Cvss3xEnvironmental.ModifiedUserInteraction = randomFromSlice([]vector.Vector{
		vector.UserInteractionNotDefined, vector.ModifiedUserInteractionNone,
		vector.ModifiedUserInteractionRequired,
	})
	result.Cvss3xEnvironmental.ModifiedScope = randomFromSlice([]vector.Vector{
		vector.ScopeNotDefined, vector.ModifiedScopeUnchanged,
		vector.ModifiedScopeChanged,
	})
	result.Cvss3xEnvironmental.ModifiedConfidentiality = randomFromSlice([]vector.Vector{
		vector.ConfidentialityNotDefined, vector.ModifiedConfidentialityNone,
		vector.ModifiedConfidentialityLow, vector.ModifiedConfidentialityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedIntegrity = randomFromSlice([]vector.Vector{
		vector.IntegrityNotDefined, vector.ModifiedIntegrityNone,
		vector.ModifiedIntegrityLow, vector.ModifiedIntegrityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedAvailability = randomFromSlice([]vector.Vector{
		vector.AvailabilityNotDefined, vector.ModifiedAvailabilityNone,
		vector.ModifiedAvailabilityLow, vector.ModifiedAvailabilityHigh,
	})

	return result
}

// RandomCvss3xVectorString 生成一个随机的 CVSS 3.x 向量字符串
func RandomCvss3xVectorString(minorVersion int) string {
	return RandomCvss3x(minorVersion).String()
}

// RandomCvss3xWithScore 生成一个随机 CVSS 3.x 对象并计算评分
// 返回对象和评分，如果计算出错则返回错误
func RandomCvss3xWithScore(minorVersion int) (*cvss.Cvss3x, float64, error) {
	return calculateRandomScore(RandomCvss3x(minorVersion))
}

// calculateRandomScore 对给定的 CVSS 对象计算评分。
// 提取为独立函数以便对错误路径进行测试：RandomCvss3x 生成的向量必然合法，
// Calculate 不会失败，但调用方仍可能传入无效对象（例如缺失基础指标），
// 此时错误会被如实包装返回。
func calculateRandomScore(obj *cvss.Cvss3x) (*cvss.Cvss3x, float64, error) {
	calc := cvss.NewCalculator(obj)
	score, err := calc.Calculate()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to calculate score: %w", err)
	}
	return obj, score, nil
}

func randomFromSlice(options []vector.Vector) vector.Vector {
	return options[rand.Intn(len(options))]
}
