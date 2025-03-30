package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

var (
	// ErrParserMagicHead 解析的时候魔术头不合法
	ErrParserMagicHead = errors.New("cvss 3.x parser error, magic head valid, it must equals 'CVSS' ")
)

const (
	CVSSMagicHead = "CVSS"
)

// Cvss3xParser
// CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
type Cvss3xParser struct {
	cvss3xStr string
	csvv3x    *cvss.Cvss3x

	// 解析使用的上下文
	cvss3xRunes []rune
	i           int
}

func NewCvss3xParser(cvss3xStr string) *Cvss3xParser {
	return &Cvss3xParser{
		cvss3xStr:   cvss3xStr,
		cvss3xRunes: []rune(cvss3xStr),
		i:           0,
	}
}

func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error) {
	x.csvv3x = cvss.NewCvss3x()

	// 读取魔术头CVSS
	if err := x.readMagicHead(); err != nil {
		return nil, err
	}

	// 读取版本号
	if err := x.readVersion(); err != nil {
		return nil, err
	}

	// 向量以 / 开头，确保当前位置是 /
	if x.isNotEnd() && x.cvss3xRunes[x.i] != '/' {
		return nil, fmt.Errorf("cvss3x %s syntax error at %d, expected '/' but got '%c'", x.cvss3xStr, x.i, x.cvss3xRunes[x.i])
	}

	// 每个向量的格式都是 /KEY:VALUE
	for x.isNotEnd() {
		// 跳过 /
		x.i++

		// 读取键
		key, err := x.readKey()
		if err != nil {
			return nil, err
		}

		// 读取值
		value, err := x.readValue()
		if err != nil {
			return nil, err
		}

		// 映射向量到CVSS结构
		if err := x.mapVectorToStruct(key, value); err != nil {
			return nil, err
		}
	}

	return x.csvv3x, nil
}

// 读取魔术头，固定的CVSS
func (x *Cvss3xParser) readMagicHead() error {
	if len(x.cvss3xRunes) < 5 { // 最少需要 "CVSS:"
		return ErrParserMagicHead
	}

	// 检查 "CVSS:" 前缀
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
	x.csvv3x.MajorVersion = majorVersion

	// 副版本号
	minorVersion, err := x.readMinorVersion()
	if err != nil {
		return err
	}
	x.csvv3x.MinorVersion = minorVersion

	return nil
}

// 读取主版本
func (x *Cvss3xParser) readMajorVersion() (int, error) {
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '.' {
			break
		}
		slice = append(slice, c)
	}

	if len(slice) == 0 {
		return 0, fmt.Errorf("empty major version")
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
		return "", fmt.Errorf("cvss3x %s synctax error at %d", x.cvss3xStr, x.i)
	}

	// 然后再是读到一个 / 或者是结束
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '/' {
			x.i--
			break
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
		x.csvv3x.Cvss3xBase.AttackVector = vectorObj
	case "AC": // Attack Complexity
		x.csvv3x.Cvss3xBase.AttackComplexity = vectorObj
	case "PR": // Privileges Required
		x.csvv3x.Cvss3xBase.PrivilegesRequired = vectorObj
	case "UI": // User Interaction
		x.csvv3x.Cvss3xBase.UserInteraction = vectorObj
	case "S": // Scope
		x.csvv3x.Cvss3xBase.Scope = vectorObj
	case "C": // Confidentiality Impact
		x.csvv3x.Cvss3xBase.Confidentiality = vectorObj
	case "I": // Integrity Impact
		x.csvv3x.Cvss3xBase.Integrity = vectorObj
	case "A": // Availability Impact
		x.csvv3x.Cvss3xBase.Availability = vectorObj

	// Temporal指标
	case "E": // Exploit Code Maturity
		x.csvv3x.Cvss3xTemporal.ExploitCodeMaturity = vectorObj
	case "RL": // Remediation Level
		x.csvv3x.Cvss3xTemporal.RemediationLevel = vectorObj
	case "RC": // Report Confidence
		x.csvv3x.Cvss3xTemporal.ReportConfidence = vectorObj

	// Environmental指标
	case "CR": // Confidentiality Requirement
		x.csvv3x.Cvss3xEnvironmental.ConfidentialityRequirement = vectorObj
	case "IR": // Integrity Requirement
		x.csvv3x.Cvss3xEnvironmental.IntegrityRequirement = vectorObj
	case "AR": // Availability Requirement
		x.csvv3x.Cvss3xEnvironmental.AvailabilityRequirement = vectorObj
	case "MAV": // Modified Attack Vector
		x.csvv3x.Cvss3xEnvironmental.ModifiedAttackVector = vectorObj
	case "MAC": // Modified Attack Complexity
		x.csvv3x.Cvss3xEnvironmental.ModifiedAttackComplexity = vectorObj
	case "MPR": // Modified Privileges Required
		x.csvv3x.Cvss3xEnvironmental.ModifiedPrivilegesRequired = vectorObj
	case "MUI": // Modified User Interaction
		x.csvv3x.Cvss3xEnvironmental.ModifiedUserInteraction = vectorObj
	case "MS": // Modified Scope
		x.csvv3x.Cvss3xEnvironmental.ModifiedScope = vectorObj
	case "MC": // Modified Confidentiality Impact
		x.csvv3x.Cvss3xEnvironmental.ModifiedConfidentiality = vectorObj
	case "MI": // Modified Integrity Impact
		x.csvv3x.Cvss3xEnvironmental.ModifiedIntegrity = vectorObj
	case "MA": // Modified Availability Impact
		x.csvv3x.Cvss3xEnvironmental.ModifiedAvailability = vectorObj
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
