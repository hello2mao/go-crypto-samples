package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	//secp256r1 (P256) curve
	p256 := elliptic.P256()

	// gen key
	privKey, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		fmt.Printf("ecdsa.GenerateKey err: %v", err)
		os.Exit(-1)
	}
	fmt.Printf("PrivKey.D: %v\n", privKey.D)
	fmt.Printf("PublicKey.X: %v\n", privKey.X)
	fmt.Printf("PublicKey.Y: %v\n", privKey.Y)

	data := "helloworld"
	hashedData := sha256.Sum256([]byte(data))

	// way-1
	{
		r, s, err := ecdsa.Sign(rand.Reader, privKey, hashedData[:])
		if err != nil {
			fmt.Printf("ecdsa.Sign err: %v\n", err)
			os.Exit(-1)
		}
		if !ecdsa.Verify(&privKey.PublicKey, hashedData[:], r, s) {
			fmt.Printf("ecdsa.Verify failed\n")
			os.Exit(-1)
		}
		fmt.Printf("[1]sign and verify success\n")
	}

	// way-2
	// go version >= 1.15
	//{
	//	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hashedData[:])
	//	if err != nil {
	//		fmt.Printf("ecdsa.SignASN1 err: %v\n", err)
	//		os.Exit(-1)
	//	}
	//	if !ecdsa.VerifyASN1(&privKey.PublicKey, hashedData[:], signature) {
	//		fmt.Printf("ecdsa.Verify failed\n")
	//		os.Exit(-1)
	//	}
	//	fmt.Printf("[2]sign and verify success\n")
	//}

}
