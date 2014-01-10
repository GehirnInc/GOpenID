package gopenid

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBTWOC(t *testing.T) {
	assert.Equal(t, BTWOC(0), "\\x00")
	assert.Equal(t, BTWOC(127), "\\x7F")
	assert.Equal(t, BTWOC(128), "\\x00\\x80")
	assert.Equal(t, BTWOC(255), "\\x00\\xFF")
	assert.Equal(t, BTWOC(32768), "\\x00\\x80\\x00")
}
