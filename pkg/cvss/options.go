package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// Option 是 Cvss3x 的 Functional Option 函数类型
// 遵循 Go 惯用的 Functional Options 模式，允许灵活组合参数
type Option func(*Cvss3x) error

// NewCvss3xWithOptions 使用 Functional Options 模式创建 Cvss3x 对象
// 支持任意组合的选项，新增选项不破坏已有调用
//
// 用法:
//
//	cv, err := cvss.NewCvss3xWithOptions(
//	    cvss.WithVersion(3, 1),
//	    cvss.WithAV('N'),
//	    cvss.WithAC('L'),
//	    cvss.WithPR('N'),
//	    cvss.WithUI('N'),
//	    cvss.WithS('U'),
//	    cvss.WithC('H'),
//	    cvss.WithI('H'),
//	    cvss.WithA('H'),
//	)
func NewCvss3xWithOptions(opts ...Option) (*Cvss3x, error) {
	cvss := &Cvss3x{
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
		MajorVersion:        3,
		MinorVersion:        1,
	}
	for _, opt := range opts {
		if err := opt(cvss); err != nil {
			return nil, err
		}
	}
	return cvss, nil
}

// MustNewCvss3xWithOptions 使用 Functional Options 模式创建 Cvss3x 对象，出错则 panic
func MustNewCvss3xWithOptions(opts ...Option) *Cvss3x {
	result, err := NewCvss3xWithOptions(opts...)
	if err != nil {
		panic(err)
	}
	return result
}

// --- Version ---

// WithVersion 设置 CVSS 版本号
func WithVersion(major, minor int) Option {
	return func(c *Cvss3x) error {
		c.MajorVersion = major
		c.MinorVersion = minor
		return nil
	}
}

// WithVersion31 设置为 CVSS 3.1 版本
func WithVersion31() Option {
	return WithVersion(3, 1)
}

// WithVersion30 设置为 CVSS 3.0 版本
func WithVersion30() Option {
	return WithVersion(3, 0)
}

// --- Base Metrics ---

// WithAV 设置 Attack Vector
func WithAV(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetAttackVector(val)
		if err != nil {
			return fmt.Errorf("AV: %w", err)
		}
		c.Cvss3xBase.AttackVector = v
		return nil
	}
}

// WithAC 设置 Attack Complexity
func WithAC(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetAttackComplexity(val)
		if err != nil {
			return fmt.Errorf("AC: %w", err)
		}
		c.Cvss3xBase.AttackComplexity = v
		return nil
	}
}

// WithPR 设置 Privileges Required
func WithPR(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetPrivilegesRequired(val)
		if err != nil {
			return fmt.Errorf("PR: %w", err)
		}
		c.Cvss3xBase.PrivilegesRequired = v
		return nil
	}
}

// WithUI 设置 User Interaction
func WithUI(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetUserInteraction(val)
		if err != nil {
			return fmt.Errorf("UI: %w", err)
		}
		c.Cvss3xBase.UserInteraction = v
		return nil
	}
}

// WithS 设置 Scope
func WithS(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetScope(val)
		if err != nil {
			return fmt.Errorf("S: %w", err)
		}
		c.Cvss3xBase.Scope = v
		return nil
	}
}

// WithC 设置 Confidentiality Impact
func WithC(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetConfidentiality(val)
		if err != nil {
			return fmt.Errorf("C: %w", err)
		}
		c.Cvss3xBase.Confidentiality = v
		return nil
	}
}

// WithI 设置 Integrity Impact
func WithI(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetIntegrity(val)
		if err != nil {
			return fmt.Errorf("I: %w", err)
		}
		c.Cvss3xBase.Integrity = v
		return nil
	}
}

// WithA 设置 Availability Impact
func WithA(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetAvailability(val)
		if err != nil {
			return fmt.Errorf("A: %w", err)
		}
		c.Cvss3xBase.Availability = v
		return nil
	}
}

// --- Temporal Metrics ---

// WithE 设置 Exploit Code Maturity
func WithE(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetExploitCodeMaturity(val)
		if err != nil {
			return fmt.Errorf("E: %w", err)
		}
		if c.Cvss3xTemporal == nil {
			c.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		c.Cvss3xTemporal.ExploitCodeMaturity = v
		return nil
	}
}

// WithRL 设置 Remediation Level
func WithRL(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetRemediationLevel(val)
		if err != nil {
			return fmt.Errorf("RL: %w", err)
		}
		if c.Cvss3xTemporal == nil {
			c.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		c.Cvss3xTemporal.RemediationLevel = v
		return nil
	}
}

// WithRC 设置 Report Confidence
func WithRC(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetReportConfidence(val)
		if err != nil {
			return fmt.Errorf("RC: %w", err)
		}
		if c.Cvss3xTemporal == nil {
			c.Cvss3xTemporal = &Cvss3xTemporal{}
		}
		c.Cvss3xTemporal.ReportConfidence = v
		return nil
	}
}

// WithTemporal 一次性设置三个时间指标
func WithTemporal(e, rl, rc rune) Option {
	return func(c *Cvss3x) error {
		// 使用各个单独的 Option 并依次应用
		for _, opt := range []Option{WithE(e), WithRL(rl), WithRC(rc)} {
			if err := opt(c); err != nil {
				return err
			}
		}
		return nil
	}
}

// --- Environmental Metrics ---

// WithCR 设置 Confidentiality Requirement
func WithCR(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetConfidentialityRequirement(val)
		if err != nil {
			return fmt.Errorf("CR: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ConfidentialityRequirement = v
		return nil
	}
}

// WithIR 设置 Integrity Requirement
func WithIR(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetIntegrityRequirement(val)
		if err != nil {
			return fmt.Errorf("IR: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.IntegrityRequirement = v
		return nil
	}
}

// WithAR 设置 Availability Requirement
func WithAR(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetAvailabilityRequirement(val)
		if err != nil {
			return fmt.Errorf("AR: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.AvailabilityRequirement = v
		return nil
	}
}

// WithRequirements 一次性设置三个安全需求指标
func WithRequirements(cr, ir, ar rune) Option {
	return func(c *Cvss3x) error {
		for _, opt := range []Option{WithCR(cr), WithIR(ir), WithAR(ar)} {
			if err := opt(c); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithMAV 设置 Modified Attack Vector
func WithMAV(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedAttackVector(val)
		if err != nil {
			return fmt.Errorf("MAV: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedAttackVector = v
		return nil
	}
}

// WithMAC 设置 Modified Attack Complexity
func WithMAC(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedAttackComplexity(val)
		if err != nil {
			return fmt.Errorf("MAC: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedAttackComplexity = v
		return nil
	}
}

// WithMPR 设置 Modified Privileges Required
func WithMPR(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedPrivilegesRequired(val)
		if err != nil {
			return fmt.Errorf("MPR: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedPrivilegesRequired = v
		return nil
	}
}

// WithMUI 设置 Modified User Interaction
func WithMUI(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedUserInteraction(val)
		if err != nil {
			return fmt.Errorf("MUI: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedUserInteraction = v
		return nil
	}
}

// WithMS 设置 Modified Scope
func WithMS(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedScope(val)
		if err != nil {
			return fmt.Errorf("MS: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedScope = v
		return nil
	}
}

// WithMC 设置 Modified Confidentiality Impact
func WithMC(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedConfidentiality(val)
		if err != nil {
			return fmt.Errorf("MC: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedConfidentiality = v
		return nil
	}
}

// WithMI 设置 Modified Integrity Impact
func WithMI(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedIntegrity(val)
		if err != nil {
			return fmt.Errorf("MI: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedIntegrity = v
		return nil
	}
}

// WithMA 设置 Modified Availability Impact
func WithMA(val rune) Option {
	return func(c *Cvss3x) error {
		v, err := vector.GetModifiedAvailability(val)
		if err != nil {
			return fmt.Errorf("MA: %w", err)
		}
		if c.Cvss3xEnvironmental == nil {
			c.Cvss3xEnvironmental = &Cvss3xEnvironmental{}
		}
		c.Cvss3xEnvironmental.ModifiedAvailability = v
		return nil
	}
}

// --- 预设组合 ---

// applyPresets 依次应用一组预设 Option。预设值均为硬编码的合法常量，
// 各 Option 不会返回错误，因此这里不检查错误以避免不可达分支。
func applyPresets(c *Cvss3x, opts []Option) error {
	for _, opt := range opts {
		_ = opt(c)
	}
	return nil
}

// WithCriticalBase 设置一个 Critical 级别的基础指标预设 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
func WithCriticalBase() Option {
	return func(c *Cvss3x) error {
		return applyPresets(c, []Option{
			WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
			WithS('C'), WithC('H'), WithI('H'), WithA('H'),
		})
	}
}

// WithHighBase 设置一个 High 级别的基础指标预设 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
func WithHighBase() Option {
	return func(c *Cvss3x) error {
		return applyPresets(c, []Option{
			WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
			WithS('U'), WithC('H'), WithI('H'), WithA('H'),
		})
	}
}

// WithMediumBase 设置一个 Medium 级别的基础指标预设 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
func WithMediumBase() Option {
	return func(c *Cvss3x) error {
		return applyPresets(c, []Option{
			WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
			WithS('U'), WithC('L'), WithI('L'), WithA('N'),
		})
	}
}

// WithLowBase 设置一个 Low 级别的基础指标预设 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)
func WithLowBase() Option {
	return func(c *Cvss3x) error {
		return applyPresets(c, []Option{
			WithAV('N'), WithAC('H'), WithPR('N'), WithUI('R'),
			WithS('U'), WithC('L'), WithI('N'), WithA('N'),
		})
	}
}

// WithNoneBase 设置一个 None 级别的基础指标预设 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N)
func WithNoneBase() Option {
	return func(c *Cvss3x) error {
		return applyPresets(c, []Option{
			WithAV('N'), WithAC('L'), WithPR('N'), WithUI('N'),
			WithS('U'), WithC('N'), WithI('N'), WithA('N'),
		})
	}
}
