package vector

type Scope struct {
	*VectorImpl
}

var _ Vector = &Scope{}

var (
	ScopeUnchanged = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "S",
			LongName:    "Scope",
			ShortValue:  'U',
			LongValue:   "Unchanged",
			Description: `An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.`,
			Score:       0,
		},
	}

	ScopeChanged = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "S",
			LongName:    "Scope",
			ShortValue:  'C',
			LongValue:   "Changed",
			Description: `An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.`,
			Score:       0,
		},
	}
)

var (
	ModifiedScopeUnchanged = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MS",
			LongName:    "Modified Scope",
			ShortValue:  'U',
			LongValue:   "Unchanged",
			Description: `An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.`,
			Score:       0,
		},
	}

	ModifiedScopeChanged = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MS",
			LongName:    "Modified Scope",
			ShortValue:  'C',
			LongValue:   "Changed",
			Description: `An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.`,
			Score:       0,
		},
	}
)
