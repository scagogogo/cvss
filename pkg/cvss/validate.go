package cvss

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// ValidationError 表示 CVSS 验证失败的结构化错误
// 包含具体哪些指标缺失或无效的信息
type ValidationError struct {
	Metric  string // 缺失或无效的指标短名称，如 "AV", "PR", "E"
	Message string // 人类可读的错误描述
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("metric %s: %s", e.Metric, e.Message)
}

// ValidationErrors 收集多个验证错误
type ValidationErrors []*ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(msgs, "; "))
}

// MissingMetrics 返回所有缺失的指标名称列表
func (ve ValidationErrors) MissingMetrics() []string {
	names := make([]string, 0, len(ve))
	for _, e := range ve {
		names = append(names, e.Metric)
	}
	return names
}

// HasErrors 判断是否有验证错误
func (ve ValidationErrors) HasErrors() bool {
	return len(ve) > 0
}

// Unwrap 实现 Go 1.20+ 多错误解包接口
// 允许 errors.Is 和 errors.As 遍历所有验证错误
func (ve ValidationErrors) Unwrap() []error {
	errs := make([]error, len(ve))
	for i, e := range ve {
		errs[i] = e
	}
	return errs
}

// Validate 验证 CVSS 向量的完整性，返回所有缺失/无效的指标
// 与 Check() 不同，Validate 不会在第一个错误时短路，而是收集所有错误
func (x *Cvss3x) Validate() error {
	if x == nil {
		return ValidationErrors{{Metric: "Cvss3x", Message: "is nil"}}
	}

	var errs ValidationErrors

	// 版本验证
	if x.MajorVersion != 3 {
		errs = append(errs, &ValidationError{
			Metric:  "Version",
			Message: fmt.Sprintf("unsupported major version %d, only 3 is supported", x.MajorVersion),
		})
	}
	if x.MinorVersion != 0 && x.MinorVersion != 1 {
		errs = append(errs, &ValidationError{
			Metric:  "Version",
			Message: fmt.Sprintf("unsupported minor version %d, only 3.0 and 3.1 are supported", x.MinorVersion),
		})
	}

	// 基础指标验证 — 逐个检查，不短路
	if x.Cvss3xBase == nil {
		errs = append(errs, &ValidationError{Metric: "Base", Message: "base metrics are nil"})
	} else {
		baseChecks := []struct {
			metric string
			vector vector.Vector
		}{
			{"AV", x.Cvss3xBase.AttackVector},
			{"AC", x.Cvss3xBase.AttackComplexity},
			{"PR", x.Cvss3xBase.PrivilegesRequired},
			{"UI", x.Cvss3xBase.UserInteraction},
			{"S", x.Cvss3xBase.Scope},
			{"C", x.Cvss3xBase.Confidentiality},
			{"I", x.Cvss3xBase.Integrity},
			{"A", x.Cvss3xBase.Availability},
		}
		for _, c := range baseChecks {
			if c.vector == nil {
				errs = append(errs, &ValidationError{
					Metric:  c.metric,
					Message: "is required but not set",
				})
			}
		}
	}

	// 时间指标验证 — 检查已设置的指标名称是否正确
	if x.Cvss3xTemporal != nil {
		temporalChecks := []struct {
			metric    string
			vector    vector.Vector
			shortName string
		}{
			{"E", x.Cvss3xTemporal.ExploitCodeMaturity, "E"},
			{"RL", x.Cvss3xTemporal.RemediationLevel, "RL"},
			{"RC", x.Cvss3xTemporal.ReportConfidence, "RC"},
		}
		for _, c := range temporalChecks {
			if c.vector != nil && c.vector.GetShortName() != c.shortName {
				errs = append(errs, &ValidationError{
					Metric:  c.metric,
					Message: fmt.Sprintf("expected short name %s but got %s", c.shortName, c.vector.GetShortName()),
				})
			}
		}
	}

	// 环境指标验证 — 检查已设置的指标名称是否正确
	if x.Cvss3xEnvironmental != nil {
		envChecks := []struct {
			metric    string
			vector    vector.Vector
			shortName string
		}{
			{"CR", x.Cvss3xEnvironmental.ConfidentialityRequirement, "CR"},
			{"IR", x.Cvss3xEnvironmental.IntegrityRequirement, "IR"},
			{"AR", x.Cvss3xEnvironmental.AvailabilityRequirement, "AR"},
			{"MAV", x.Cvss3xEnvironmental.ModifiedAttackVector, "MAV"},
			{"MAC", x.Cvss3xEnvironmental.ModifiedAttackComplexity, "MAC"},
			{"MPR", x.Cvss3xEnvironmental.ModifiedPrivilegesRequired, "MPR"},
			{"MUI", x.Cvss3xEnvironmental.ModifiedUserInteraction, "MUI"},
			{"MS", x.Cvss3xEnvironmental.ModifiedScope, "MS"},
			{"MC", x.Cvss3xEnvironmental.ModifiedConfidentiality, "MC"},
			{"MI", x.Cvss3xEnvironmental.ModifiedIntegrity, "MI"},
			{"MA", x.Cvss3xEnvironmental.ModifiedAvailability, "MA"},
		}
		for _, c := range envChecks {
			if c.vector != nil && c.vector.GetShortName() != c.shortName {
				errs = append(errs, &ValidationError{
					Metric:  c.metric,
					Message: fmt.Sprintf("expected short name %s but got %s", c.shortName, c.vector.GetShortName()),
				})
			}
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// MissingMetrics 返回所有缺失的基础指标名称列表
// 这是一个便捷方法，等价于调用 Validate() 并提取缺失指标名
func (x *Cvss3x) MissingMetrics() []string {
	err := x.Validate()
	if err == nil {
		return nil
	}
	// Validate() 只返回 nil 或 ValidationErrors，类型断言必成功
	ve := err.(ValidationErrors)
	var missing []string
	for _, e := range ve {
		if e.Message == "is required but not set" {
			missing = append(missing, e.Metric)
		}
	}
	return missing
}
