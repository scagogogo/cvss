package vector

type PrivilegesRequired struct {
	*VectorImpl
}

var _ Vector = &PrivilegesRequired{}

var (
	PrivilegesRequiredNone = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.`,
			Score:       0.85,
		},
	}

	PrivilegesRequiredLow = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.`,
			// TODO 0.62 (or 0.68 if Scope / Modified Scope is Changed)
			Score: 0.62,
		},
	}

	PrivilegesRequiredHigh = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.`,
			// TODO 	0.27 (or 0.5 if Scope / Modified Scope is Changed)
			Score: 0.27,
		},
	}
)

var (
	ModifiedPrivilegesRequiredNone = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.`,
			Score:       0.85,
		},
	}

	ModifiedPrivilegesRequiredLow = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.`,
			// TODO 0.62 (or 0.68 if Scope / Modified Scope is Changed)
			Score: 0.62,
		},
	}

	ModifiedPrivilegesRequiredHigh = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.`,
			// TODO 	0.27 (or 0.5 if Scope / Modified Scope is Changed)
			Score: 0.27,
		},
	}
)
