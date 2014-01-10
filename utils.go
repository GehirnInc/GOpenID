package gopenid

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func generateRandomString(length int) string {
	str := make([]rune, length)

	for i := 0; i < length; i++ {
		j, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			panic(err)
		}

		if j.Uint64() < 10 {
			str[i] = rune(j.Uint64() + 48)
		} else if j.Uint64() < 36 {
			str[i] = rune(j.Uint64() + 55)
		} else {
			str[i] = rune(j.Uint64() + 61)
		}
	}

	return string(str)
}

func GenerateNonce(now time.Time) MessageValue {
	salt := generateRandomString(6)
	ts := now.UTC().Format(time.RFC3339)

	return MessageValue(ts + salt)
}

func BTWOC(i int64) string {
	bytes := big.NewInt(int64(i)).Bytes()

	if len(bytes) < 1 || bytes[0] > 0x7f {
		ret := bytes
		bytes = make([]byte, len(ret)+1)

		copy(bytes[1:], ret)
	}

	hex := make([]string, len(bytes))
	for i, b := range bytes {
		hex[i] = fmt.Sprintf("\\x%02X", b)
	}

	return strings.Join(hex, "")
}
