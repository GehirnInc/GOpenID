package gopenid

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"math/big"
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

func IntToBase64(i *big.Int) (output []byte, err error) {
	encoded := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.StdEncoding, encoded)

	encoder.Write(i.Bytes())
	encoder.Close()

	return ioutil.ReadAll(encoded)
}

func Base64ToInt(input []byte) (i *big.Int, err error) {
	encoded := bytes.NewReader(input)
	decoded := base64.NewDecoder(base64.StdEncoding, encoded)

	buf, err := ioutil.ReadAll(decoded)
	if err != nil {
		return
	}

	i = new(big.Int).SetBytes(buf)
	return
}
