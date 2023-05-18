package cvss

import (
	"github.com/scagogogo/cvss-parser/pkg/vector"
	"strings"
)

type Cvss3xEnvironmental struct {
	ConfidentialityRequirement vector.Vector
	IntegrityRequirement       vector.Vector
	AvailabilityRequirement    vector.Vector

	ModifiedAttackVector vector.Vector

	ModifiedAttackComplexity vector.Vector

	ModifiedPrivilegesRequired vector.Vector

	ModifiedUserInteraction vector.Vector

	ModifiedScope vector.Vector

	ModifiedConfidentiality vector.Vector

	ModifiedIntegrity vector.Vector

	ModifiedAvailability vector.Vector
}

func (x *Cvss3xEnvironmental) String() string {
	slice := make([]string, 0)

	if x.ConfidentialityRequirement != nil {
		slice = append(slice, x.ConfidentialityRequirement.String())
	}

	if x.IntegrityRequirement != nil {
		slice = append(slice, x.IntegrityRequirement.String())
	}

	if x.AvailabilityRequirement != nil {
		slice = append(slice, x.AvailabilityRequirement.String())
	}

	if x.ModifiedAttackVector != nil {
		slice = append(slice, x.ModifiedAttackVector.String())
	}

	if x.ModifiedAttackComplexity != nil {
		slice = append(slice, x.ModifiedAttackComplexity.String())
	}

	if x.ModifiedPrivilegesRequired != nil {
		slice = append(slice, x.ModifiedPrivilegesRequired.String())
	}

	if x.ModifiedUserInteraction != nil {
		slice = append(slice, x.ModifiedUserInteraction.String())
	}

	if x.ModifiedScope != nil {
		slice = append(slice, x.ModifiedScope.String())
	}

	if x.ModifiedConfidentiality != nil {
		slice = append(slice, x.ModifiedConfidentiality.String())
	}

	if x.ModifiedIntegrity != nil {
		slice = append(slice, x.ModifiedIntegrity.String())
	}

	if x.ModifiedAvailability != nil {
		slice = append(slice, x.ModifiedAvailability.String())
	}

	return strings.Join(slice, "/")
}
