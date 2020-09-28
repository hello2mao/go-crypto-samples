package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
)

// GenerateSharedSecret takes in a public key and a private key
// and generates a shared secret.
//
// RFC5903 Section 9 states we should only return x.
func GenerateSharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if privKey.Params().Name != pubKey.Params().Name {
		return nil, fmt.Errorf("privKey and pubKey not the same curve")
	}

	x, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	return x.Bytes(), nil
}

func main() {

	privKeyServer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("ecdsa.GenerateKey err: %v", err)
		os.Exit(-1)
	}
	privKeyClient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("ecdsa.GenerateKey err: %v", err)
		os.Exit(-1)
	}

	sharedKeyServer, err := GenerateSharedSecret(privKeyServer, &privKeyClient.PublicKey)
	if err != nil {
		fmt.Printf("GenerateSharedSecret err: %v", err)
		os.Exit(-1)
	}
	fmt.Printf("sharedKeyServer: %v\n", sharedKeyServer)
	sharedKeyClient, err := GenerateSharedSecret(privKeyClient, &privKeyServer.PublicKey)
	if err != nil {
		fmt.Printf("GenerateSharedSecret err: %v", err)
		os.Exit(-1)
	}
	fmt.Printf("sharedKeyClient: %v\n", sharedKeyClient)

	if !bytes.Equal(sharedKeyServer, sharedKeyClient) {
		fmt.Printf("sharedKey not equal.")
		os.Exit(-1)
	}
}
