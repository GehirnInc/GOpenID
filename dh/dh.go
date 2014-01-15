package dh

import (
	"crypto/rand"
	"io"
	"math/big"
)

var (
	bigZero = new(big.Int).SetInt64(0)
)

type Params struct {
	P *big.Int // modulus
	G *big.Int // generator
}

type SharedSecret struct {
	ZZ *big.Int
}

type PrivateKey struct {
	X *big.Int
	Params
	PublicKey
}

func GenerateKey(random io.Reader, bits int, params Params) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.X, err = rand.Int(rand.Reader, params.P)
	if err != nil {
		return
	} else if priv.X.Cmp(bigZero) < 1 {
		return GenerateKey(random, bits, params)
	}

	priv.Y = new(big.Int).Exp(params.G, priv.X, params.P)
	priv.Params = params
	return
}

func (priv *PrivateKey) SharedSecret(pub PublicKey) *SharedSecret {
	return &SharedSecret{
		ZZ: new(big.Int).Exp(pub.Y, priv.X, priv.P),
	}
}

type PublicKey struct {
	Y *big.Int
}
