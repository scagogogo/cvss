package cvss

import (
	"github.com/scagogogo/cvss-parser/pkg/vector"
	"strings"
)

type Cvss3xTemporal struct {
	ExploitCodeMaturity vector.Vector
	RemediationLevel    vector.Vector
	ReportConfidence    vector.Vector
}

func (x *Cvss3xTemporal) String() string {
	slice := make([]string, 0)

	if x.ExploitCodeMaturity != nil {
		slice = append(slice, x.ExploitCodeMaturity.String())
	}

	if x.RemediationLevel != nil {
		slice = append(slice, x.RemediationLevel.String())
	}

	if x.ReportConfidence != nil {
		slice = append(slice, x.ReportConfidence.String())
	}

	return strings.Join(slice, "/")
}
