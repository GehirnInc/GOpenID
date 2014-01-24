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

func EncodeBase64(input []byte) (b []byte) {
	encoded := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.StdEncoding, encoded)

	encoder.Write(input)
	encoder.Close()

	b, _ = ioutil.ReadAll(encoded)
	return
}

func DecodeBase64(encoded []byte) (buf []byte, err error) {
	reader := bytes.NewReader(encoded)
	decoded := base64.NewDecoder(base64.StdEncoding, reader)
	buf, err = ioutil.ReadAll(decoded)
	return
}

func IntToBase64(i *big.Int) (output []byte) {
	return EncodeBase64(i.Bytes())
}

func Base64ToInt(input []byte) (i *big.Int, err error) {
	buf, err := DecodeBase64(input)
	if err != nil {
		return
	}

	i = new(big.Int).SetBytes(buf)
	return
}
