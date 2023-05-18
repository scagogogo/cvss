package vector

type UserInteraction struct {
	*VectorImpl
}

var _ Vector = &UserInteraction{}

var (
	UserInteractionNone = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "UI",
			LongName:    "User Interaction",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The vulnerable system can be exploited without interaction from any user.`,
			Score:       0.85,
		},
	}

	UserInteractionRequired = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "UI",
			LongName:    "User Interaction",
			ShortValue:  'R',
			LongValue:   "Required",
			Description: `Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.`,
			Score:       0.62,
		},
	}
)

var (
	ModifiedUserInteractionNone = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The vulnerable system can be exploited without interaction from any user.`,
			Score:       0.85,
		},
	}

	ModifiedUserInteractionRequired = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'R',
			LongValue:   "Required",
			Description: `Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.`,
			Score:       0.62,
		},
	}
)
