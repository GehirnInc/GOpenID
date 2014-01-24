package gopenid

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

type SwitchWithBase64AndIntCase struct {
	b64  string
	ints string
	int_ *big.Int
}

var (
	switchWithBase64AndIntCases = []SwitchWithBase64AndIntCase{
		SwitchWithBase64AndIntCase{
			b64:  "YzMEHYRgZABmW1SbBLtJ/hXJ2FtAmxM/rz0hfCfoIujQLOalLn9p5AOvcHP1eJ3RRF8trd0e/8bcUGnC+35jQG+T8zCkbixShGJ+6y+LW21e/rYDHUDuekPOeyITtDxJ9qUmRc52EccLoAR2TD0fd3OElq806K5kDdC6k5xHgPM=",
			ints: "69660104459313954719507736580852111525028902275855157692077983749396167954609604924964961442948594627452815453553570195109858244395153257089774496208461870849523186940193169917496165721399002725195482474365744296971229879214681370943452301194705551292483801594974327364757552830805575701818730024140360089843",
		},
	}
)

func init() {
	for x, testCase := range switchWithBase64AndIntCases {
		testCase.int_, _ = new(big.Int).SetString(testCase.ints, 10)
		switchWithBase64AndIntCases[x] = testCase
	}
}

func TestSwitchWithBase64AndInt(t *testing.T) {
	for _, testCase := range switchWithBase64AndIntCases {
		b64 := IntToBase64(testCase.int_)
		assert.Equal(t, testCase.b64, string(b64))

		int_, err := Base64ToInt([]byte(testCase.b64))
		if assert.Nil(t, err) {
			assert.Equal(t, testCase.int_, int_)
		}
	}
}
