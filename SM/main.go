package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
)

func main() {

	// 用户A公钥
	pk1Str := "MEUCIQDio0Pt1VNG80o0ZjdiVoF7Tjh1dqYil6pqXMtfdl8iggIgUGKERDIhMDxb48LQg9m6D12LVm2qeAdEz8tET59kGbk="

	// 用户B私钥
	sk2Str := "55e92bfb3dfe072605770c0c3f77fd5b342ab782aa9fee0aa686c0c8047acb5a"
	sk2Bytes, _ := hex.DecodeString(sk2Str)
	sk2 := LoadPrivateKey(sk2Bytes)

	// 密文16进制
	ciphertextHex := "4d56eb35131a8db0bf7b87dcfdff806a"

	// 用户B签名
	msg := "helloworld"
	sign, err := sk2.Sign(rand.Reader, []byte(msg), nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sign: %s\n", base64.StdEncoding.EncodeToString(sign))

	// dh
	pk1Bytes, err := base64.StdEncoding.DecodeString(pk1Str)
	if err != nil {
		panic(err)
	}
	pk1, err := DecodeASN1DERPublicKey(pk1Bytes)
	if err != nil {
		panic(err)
	}
	key, _ := sk2.PublicKey.ScalarMult(pk1.X, pk1.Y, sk2.D.Bytes())
	fmt.Printf("key2: %x\n", key.Bytes()[:16])

	// cbc decrypt
	ciphertext, _ := hex.DecodeString(ciphertextHex)
	out, err := sm4.Sm4Cbc(key.Bytes()[:16], ciphertext, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("out: %s\n", out)
}

func LoadPrivateKey(key []byte) *sm2.PrivateKey {
	c := sm2.P256Sm2()
	k := new(big.Int).SetBytes(key)
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}

func EncodePublicKeyToASN1DER(publicKey *sm2.PublicKey) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(publicKey.X)
		b.AddASN1BigInt(publicKey.Y)
	})
	return b.Bytes()
}

func DecodeASN1DERPublicKey(publicKeyASN1 []byte) (*sm2.PublicKey, error) {
	var (
		x, y  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(publicKeyASN1)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x) ||
		!inner.ReadASN1Integer(y) ||
		!inner.Empty() {
		return nil, fmt.Errorf("decode failed")
	}
	return &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}, nil
}


