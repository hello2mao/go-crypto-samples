package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
)

func main() {
	// gen key
	// privKey: (d,n)
	// pubKey: (e,n)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Printf("GenerateKey err: %v\n", err)
		os.Exit(-1)
	}
	fmt.Printf("privKey, d: %v, n: %v\n", key.D.String(), key.N.String())
	fmt.Printf("pubKey, e: %v, n: %v\n", key.PublicKey.E, key.PublicKey.N.String())
}
