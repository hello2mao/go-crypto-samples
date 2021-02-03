package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"math/big"
)

func main() {

	b := make([]byte, 256)
	_, err := rand.Reader.Read(b)
	if err != nil {
		panic(err)
	}

	// ecdsa
	{
		p256 := elliptic.P256()
		x, y := p256.ScalarBaseMult(b)
		eccPrivateKey := ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: p256,
				X:     x,
				Y:     y,
			},
			D: new(big.Int).SetBytes(b),
		}

		msg := "hello"
		hash := sha256.Sum256([]byte(msg))
		sig, err := eccPrivateKey.Sign(rand.Reader, hash[:], nil)
		if err != nil {
			panic(err)
		}

		if !ecdsa.VerifyASN1(&eccPrivateKey.PublicKey, hash[:], sig) {
			panic("VerifyASN1 failed")
		}
		fmt.Printf("ecdsa success.\n")
	}

	// sm2
	{
		p256Sm2 := sm2.P256Sm2()
		x, y := p256Sm2.ScalarBaseMult(b)
		smPrivateKey := sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: p256Sm2,
				X:     x,
				Y:     y,
			},
			D: new(big.Int).SetBytes(b),
		}

		msg := "hello"
		hash := sm3.Sm3Sum([]byte(msg))
		sig, err := smPrivateKey.Sign(rand.Reader, hash[:], nil)
		if err != nil {
			panic(err)
		}

		if !smPrivateKey.Verify(hash[:], sig) {
			panic("Verify failed")
		}
		fmt.Printf("sm2 success.\n")

	}

}
