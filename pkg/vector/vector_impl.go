package vector

import "fmt"

type VectorImpl struct {
	GroupName   string
	ShortName   string
	LongName    string
	ShortValue  rune
	LongValue   string
	Description string
	Score       float64
}

var _ Vector = &VectorImpl{}

func (x *VectorImpl) GetGroupName() string {
	return x.GroupName
}

func (x *VectorImpl) GetShortName() string {
	return x.ShortName
}

func (x *VectorImpl) GetLongName() string {
	return x.LongName
}

func (x *VectorImpl) GetShortValue() rune {
	return x.ShortValue
}

func (x *VectorImpl) GetLongValue() string {
	return x.LongValue
}

func (x *VectorImpl) GetDescription() string {
	return x.Description
}

func (x *VectorImpl) GetScore() float64 {
	return x.Score
}

func (x *VectorImpl) String() string {
	return fmt.Sprintf("%s:%c", x.ShortName, x.ShortValue)
}
