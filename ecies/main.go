package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto/ecies"
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

	plaintext := []byte("helloword")
	ct, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(&privKey.PublicKey), plaintext, nil, nil)
	if err != nil {
		fmt.Printf("ecies.Encrypt err: %v", err)
		os.Exit(-1)
	}
	pt, err := ecies.ImportECDSA(privKey).Decrypt(ct, nil, nil)
	if err != nil {
		fmt.Printf("ecies.Decrypt err: %v", err)
		os.Exit(-1)
	}
	if !bytes.Equal(plaintext, pt) {
		fmt.Printf("ecies encrypt and decrypt failed")
		os.Exit(-1)
	}
}
