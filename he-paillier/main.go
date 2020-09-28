package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/roasbeef/go-go-gadget-paillier"
)

//Encrypted integers can be added together
//Encrypted integers can be multiplied by an unencrypted integer
//Encrypted integers and unencrypted integers can be added together
func main() {
	// Generate a 128-bit private key.
	privKey, _ := paillier.GenerateKey(rand.Reader, 128)

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())

	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, _ := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())

	// Add the encrypted integers 15 and 20 together.
	plusM15M20 := paillier.AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, _ := paillier.Decrypt(privKey, plusM15M20)
	fmt.Println("Result of 15+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35!

	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := paillier.Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, _ = paillier.Decrypt(privKey, plusE15and10)
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25!

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := paillier.Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, _ := paillier.Decrypt(privKey, mulE15and10)
	fmt.Println("Result of 15*10 after decryption: ",
		new(big.Int).SetBytes(decryptedMul).String()) // 150!
}
