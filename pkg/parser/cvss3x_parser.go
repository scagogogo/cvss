package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/vector"
)

var (
	// ErrParserMagicHead 解析的时候魔术头不合法
	ErrParserMagicHead = errors.New("cvss 3.x parser error: invalid magic head, it must equal 'CVSS'")
	// ErrDuplicateMetric 表示向量字符串中存在重复的指标键
	ErrDuplicateMetric = errors.New("cvss 3.x parser error: duplicate metric key")
)

const (
	CVSSMagicHead = "CVSS"
)

// Cvss3xParser
// CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
type Cvss3xParser struct {
	cvss3xStr string
	cvss3x    *cvss.Cvss3x

	// 解析使用的上下文
	cvss3xRunes []rune
	i           int

	// 已解析的键，用于检测重复
	parsedKeys map[string]bool
}

func NewCvss3xParser(cvss3xStr string) *Cvss3xParser {
	return &Cvss3xParser{
		cvss3xStr:   strings.TrimSpace(cvss3xStr),
		cvss3xRunes: []rune(strings.TrimSpace(cvss3xStr)),
		i:           0,
		parsedKeys:  make(map[string]bool),
	}
}

func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error) {
	x.cvss3x = cvss.NewCvss3x()

	// 读取魔术头CVSS
	if err := x.readMagicHead(); err != nil {
		return nil, err
	}

	// 读取版本号
	if err := x.readVersion(); err != nil {
		return nil, err
	}

	// 向量以 / 开头，确保当前位置是 /
	if !x.isNotEnd() {
		return nil, fmt.Errorf("cvss3x %s syntax error: incomplete vector string, expected vectors after version", x.cvss3xStr)
	}
	// 此处当前位置必然是 '/'：readMinorVersion 遇到 '/' 时回退停在 '/'，
	// 否则读到末尾被上方的末尾检查拦截。每个向量形如 /KEY:VALUE，由下方循环消费。

	// 每个向量的格式都是 /KEY:VALUE
	for x.isNotEnd() {
		// 跳过 /
		x.i++
		x.skipWhitespace()

		// 读取键
		key, err := x.readKey()
		if err != nil {
			return nil, err
		}
		key = strings.ToUpper(key)

		// 检查重复键
		if x.parsedKeys[key] {
			return nil, fmt.Errorf("%w: %s appears more than once", ErrDuplicateMetric, key)
		}
		x.parsedKeys[key] = true

		// 读取值
		value, err := x.readValue()
		if err != nil {
			return nil, err
		}
		value = strings.ToUpper(value)

		// 映射向量到CVSS结构
		if err := x.mapVectorToStruct(key, value); err != nil {
			return nil, err
		}

		// 跳过尾部空白
		x.skipWhitespace()
	}

	return x.cvss3x, nil
}

// skipWhitespace 跳过空白字符
func (x *Cvss3xParser) skipWhitespace() {
	for x.isNotEnd() && (x.cvss3xRunes[x.i] == ' ' || x.cvss3xRunes[x.i] == '\t') {
		x.i++
	}
}

// 读取魔术头，固定的CVSS
func (x *Cvss3xParser) readMagicHead() error {
	if len(x.cvss3xRunes) < 5 { // 最少需要 "CVSS:"
		return ErrParserMagicHead
	}

	// 检查 "CVSS:" 前缀（大小写不敏感）
	if strings.ToUpper(string(x.cvss3xRunes[0:4])) != CVSSMagicHead || x.cvss3xRunes[4] != ':' {
		return ErrParserMagicHead
	}

	x.i += 5 // 跳过 "CVSS:"
	return nil
}

// 读取版本号
func (x *Cvss3xParser) readVersion() error {

	// 主版本号
	majorVersion, err := x.readMajorVersion()
	if err != nil {
		return err
	}
	x.cvss3x.MajorVersion = majorVersion

	// 副版本号
	minorVersion, err := x.readMinorVersion()
	if err != nil {
		return err
	}
	x.cvss3x.MinorVersion = minorVersion

	// 校验版本号范围：仅支持 3.0 和 3.1
	if majorVersion != 3 {
		return fmt.Errorf("unsupported CVSS major version: %d, only version 3 is supported", majorVersion)
	}
	if minorVersion != 0 && minorVersion != 1 {
		return fmt.Errorf("unsupported CVSS minor version: %d, only 3.0 and 3.1 are supported", minorVersion)
	}

	return nil
}

// 读取主版本
func (x *Cvss3xParser) readMajorVersion() (int, error) {
	slice := make([]rune, 0)
	foundDot := false
	for x.isNotEnd() {
		c := x.read()
		if c == '.' {
			foundDot = true
			break
		}
		slice = append(slice, c)
	}

	if len(slice) == 0 {
		return 0, fmt.Errorf("empty major version")
	}

	if !foundDot {
		return 0, fmt.Errorf("major version must be followed by '.'")
	}

	majorVersion, err := strconv.ParseInt(string(slice), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(majorVersion), nil
}

// 读取副版本
func (x *Cvss3xParser) readMinorVersion() (int, error) {
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '/' {
			x.i--
			break
		}
		slice = append(slice, c)
	}
	majorVersion, err := strconv.ParseInt(string(slice), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(majorVersion), nil
}

// 读取一个键
func (x *Cvss3xParser) readKey() (string, error) {
	// 读取到 : 前的所有字符作为key
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == ':' {
			x.i--
			break
		}
		if c == ' ' || c == '\t' {
			continue // 跳过键中的空白
		}
		slice = append(slice, c)
	}

	if len(slice) == 0 {
		return "", fmt.Errorf("cvss3x %s syntax error at %d, empty key", x.cvss3xStr, x.i)
	}

	return string(slice), nil
}

// 读取一个值
func (x *Cvss3xParser) readValue() (string, error) {

	// 首先必须是一个 :
	if x.read() != ':' {
		return "", fmt.Errorf("cvss3x %s syntax error at position %d: expected ':' before value", x.cvss3xStr, x.i)
	}

	// 然后再是读到一个 / 或者是结束
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '/' {
			x.i--
			break
		}
		if c == ' ' || c == '\t' {
			continue // 跳过值中的空白
		}
		slice = append(slice, c)
	}
	return string(slice), nil
}

// 将向量键值对映射到CVSS结构中
func (x *Cvss3xParser) mapVectorToStruct(key, value string) error {
	// 使用工厂方法获取向量对象
	vectorObj, err := vector.GetVectorByShortName(key, value)
	if err != nil {
		return err
	}

	switch key {
	// Base指标
	case "AV": // Attack Vector
		x.cvss3x.Cvss3xBase.AttackVector = vectorObj
	case "AC": // Attack Complexity
		x.cvss3x.Cvss3xBase.AttackComplexity = vectorObj
	case "PR": // Privileges Required
		x.cvss3x.Cvss3xBase.PrivilegesRequired = vectorObj
	case "UI": // User Interaction
		x.cvss3x.Cvss3xBase.UserInteraction = vectorObj
	case "S": // Scope
		x.cvss3x.Cvss3xBase.Scope = vectorObj
	case "C": // Confidentiality Impact
		x.cvss3x.Cvss3xBase.Confidentiality = vectorObj
	case "I": // Integrity Impact
		x.cvss3x.Cvss3xBase.Integrity = vectorObj
	case "A": // Availability Impact
		x.cvss3x.Cvss3xBase.Availability = vectorObj

	// Temporal指标 — 惰性初始化
	case "E": // Exploit Code Maturity
		if x.cvss3x.Cvss3xTemporal == nil {
			x.cvss3x.Cvss3xTemporal = &cvss.Cvss3xTemporal{}
		}
		x.cvss3x.Cvss3xTemporal.ExploitCodeMaturity = vectorObj
	case "RL": // Remediation Level
		if x.cvss3x.Cvss3xTemporal == nil {
			x.cvss3x.Cvss3xTemporal = &cvss.Cvss3xTemporal{}
		}
		x.cvss3x.Cvss3xTemporal.RemediationLevel = vectorObj
	case "RC": // Report Confidence
		if x.cvss3x.Cvss3xTemporal == nil {
			x.cvss3x.Cvss3xTemporal = &cvss.Cvss3xTemporal{}
		}
		x.cvss3x.Cvss3xTemporal.ReportConfidence = vectorObj

	// Environmental指标 — 惰性初始化
	case "CR": // Confidentiality Requirement
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement = vectorObj
	case "IR": // Integrity Requirement
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.IntegrityRequirement = vectorObj
	case "AR": // Availability Requirement
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.AvailabilityRequirement = vectorObj
	case "MAV": // Modified Attack Vector
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedAttackVector = vectorObj
	case "MAC": // Modified Attack Complexity
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity = vectorObj
	case "MPR": // Modified Privileges Required
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedPrivilegesRequired = vectorObj
	case "MUI": // Modified User Interaction
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedUserInteraction = vectorObj
	case "MS": // Modified Scope
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedScope = vectorObj
	case "MC": // Modified Confidentiality Impact
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality = vectorObj
	case "MI": // Modified Integrity Impact
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedIntegrity = vectorObj
	case "MA": // Modified Availability Impact
		if x.cvss3x.Cvss3xEnvironmental == nil {
			x.cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{}
		}
		x.cvss3x.Cvss3xEnvironmental.ModifiedAvailability = vectorObj
	}
	return nil
}

func (x *Cvss3xParser) isNotEnd() bool {
	return x.i < len(x.cvss3xRunes)
}

func (x *Cvss3xParser) read() rune {
	if x.i >= len(x.cvss3xRunes) {
		return 0
	} else {
		c := x.cvss3xRunes[x.i]
		x.i++
		return c
	}
}
