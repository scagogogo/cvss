package cvss

import (
	"fmt"
	"github.com/scagogogo/cvss-parser/pkg/vector"
	"strings"
)

type Cvss3xBase struct {

	// Attack VectorImpl (AV): Local
	AttackVector vector.Vector

	// Attack Complexity (AC): Low
	AttackComplexity vector.Vector

	// Privileges Required (PR): Low
	PrivilegesRequired vector.Vector

	// User Interaction (UI): None
	UserInteraction vector.Vector

	// Scope (S): Unchanged
	Scope vector.Vector

	// Confidentiality (C): None
	Confidentiality vector.Vector

	// Integrity (I): High
	Integrity vector.Vector

	// Availability (A): High
	Availability vector.Vector
}

// Check 检查CVSS编号是否合法
func (x *Cvss3xBase) Check() error {

	if x.AttackVector == nil {
		return fmt.Errorf("Attack Vector can not empty")
	}

	if x.AttackComplexity == nil {
		return fmt.Errorf("Attack Complexity can not empty")
	}

	if x.PrivilegesRequired == nil {
		return fmt.Errorf("Privileges Required can not empty")
	}

	if x.UserInteraction == nil {
		return fmt.Errorf("UserInteraction can not empty")
	}

	if x.Scope == nil {
		return fmt.Errorf("Scope can not empty")
	}

	if x.Confidentiality == nil {
		return fmt.Errorf("Confidentiality can not empty")
	}

	if x.Integrity == nil {
		return fmt.Errorf("Integrity can not empty")
	}

	if x.Availability == nil {
		return fmt.Errorf("Availability can not empty")
	}

	return nil
}

func (x *Cvss3xBase) String() string {
	slice := make([]string, 0)

	if x.AttackVector != nil {
		slice = append(slice, x.AttackVector.String())
	}

	if x.AttackComplexity != nil {
		slice = append(slice, x.AttackComplexity.String())
	}

	if x.PrivilegesRequired != nil {
		slice = append(slice, x.PrivilegesRequired.String())
	}

	if x.UserInteraction != nil {
		slice = append(slice, x.UserInteraction.String())
	}

	if x.Scope != nil {
		slice = append(slice, x.Scope.String())
	}

	if x.Confidentiality != nil {
		slice = append(slice, x.Confidentiality.String())
	}

	if x.Integrity != nil {
		slice = append(slice, x.Integrity.String())
	}

	if x.Availability != nil {
		slice = append(slice, x.Availability.String())
	}

	return strings.Join(slice, "/")
}
