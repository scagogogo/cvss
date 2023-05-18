package vector

// Vector 表示一个评价维度的向量
type Vector interface {
	GetGroupName() string

	GetShortName() string

	GetLongName() string

	GetShortValue() rune

	GetLongValue() string

	GetDescription() string

	GetScore() float64

	String() string
}
