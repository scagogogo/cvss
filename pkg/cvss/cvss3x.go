package cvss

import (
	"fmt"
	"strings"
)

// Cvss3x 表示一个3.x的编号
// CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
type Cvss3x struct {
	*Cvss3xBase
	*Cvss3xTemporal
	*Cvss3xEnvironmental

	// 主版本号
	MajorVersion int

	// 次版本号
	MinorVersion int
}

func NewCvss3x() *Cvss3x {
	return &Cvss3x{
		Cvss3xBase: &Cvss3xBase{},
		Cvss3xTemporal: &Cvss3xTemporal{},
		Cvss3xEnvironmental: &Cvss3xEnvironmental{},
	}
}

// Check TODO 2023-5-19 01:44:22 检查CVSS编号是否合法
func (x *Cvss3x) Check() error {
	if x.Cvss3xBase == nil {
		return fmt.Errorf("cvss3x base is nil")
	}
	return x.Cvss3xBase.Check()
}

func (x *Cvss3x) String() string {
	buff := strings.Builder{}
	buff.WriteString(fmt.Sprintf("CVSS:%d.%d", x.MajorVersion, x.MinorVersion))

	if x.Cvss3xBase != nil {
		s := x.Cvss3xBase.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	if x.Cvss3xTemporal != nil {
		s := x.Cvss3xTemporal.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	if x.Cvss3xEnvironmental != nil {
		s := x.Cvss3xEnvironmental.String()
		if s != "" {
			buff.WriteString("/")
			buff.WriteString(s)
		}
	}

	return buff.String()
}
