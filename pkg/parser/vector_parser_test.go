package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVectorParser_Parse(t *testing.T) {
	v, err := DefaultVectorParser.Parse("MAC", 'H')
	assert.Nil(t, err)
	assert.NotNil(t, v)
}
