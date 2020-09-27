package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
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

	// Marshall the public key
	marshalledPubKey := elliptic.Marshal(p256, privKey.X, privKey.Y)
	fmt.Printf("marshalledPubKey: %v\n", hex.EncodeToString(marshalledPubKey))

	// Marshall the public key
	marshallCompressedPubKey := elliptic.MarshalCompressed(p256, privKey.X, privKey.Y)
	fmt.Printf("marshallCompressedPubKey: %v\n", hex.EncodeToString(marshallCompressedPubKey))
}
