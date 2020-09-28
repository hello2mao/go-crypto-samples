package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"os"
)

const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

// PaddedBigBytes encodes a big integer as a big-endian byte slice. The length
// of the slice is at least n bytes.
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}

// 私钥 -> []byte
// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// []byte -> 私钥
// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = elliptic.P256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// 公钥 -> []byte
func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
}

// []byte -> 公钥
func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

// EncodePublicKeyToASN1DER encode pubKey to asn1 der, default curve is secp256r1
func EncodePublicKeyToASN1DER(publicKey *ecdsa.PublicKey) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(publicKey.X)
		b.AddASN1BigInt(publicKey.Y)
	})
	return b.Bytes()
}

// DecodeASN1DERPublicKey decode asn1 der to pubKey, default curve is secp256r1
func DecodeASN1DERPublicKey(publicKeyASN1 []byte) (*ecdsa.PublicKey, error) {
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
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

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
	fmt.Printf("PrivKey bytes: %x\n", FromECDSA(privKey))
	fmt.Printf("PublicKey.X: %v\n", privKey.X)
	fmt.Printf("PublicKey.Y: %v\n", privKey.Y)
	fmt.Printf("PublicKey bytes: %x\n", FromECDSAPub(&privKey.PublicKey))

	// test FromECDSA ToECDSA
	privKeyTmp, err := ToECDSA(FromECDSA(privKey))
	if err != nil {
		fmt.Printf("ToECDSA err: %v", err)
		os.Exit(-1)
	}
	if !privKeyTmp.Equal(privKey) {
		fmt.Printf("ecdsa transfer failed")
		os.Exit(-1)
	}
	// test FromECDSAPub ToECDSAPub
	pubKeyTmp := ToECDSAPub(FromECDSAPub(&privKey.PublicKey))
	if !pubKeyTmp.Equal(&privKey.PublicKey) {
		fmt.Printf("ecdsa pub transfer failed")
		os.Exit(-1)
	}

	encodedPubKey, err := EncodePublicKeyToASN1DER(&privKey.PublicKey)
	if err != nil {
		fmt.Printf("EncodePublicKeyToASN1DER err: %v", err)
		os.Exit(-1)
	}
	decodedPubKey, err := DecodeASN1DERPublicKey(encodedPubKey)
	if err != nil {
		fmt.Printf("DecodeASN1DERPublicKey err: %v", err)
		os.Exit(-1)
	}
	if !decodedPubKey.Equal(&privKey.PublicKey) {
		fmt.Printf("ecc encode and decode failed")
		os.Exit(-1)
	}

	// Marshall the public key
	// go version >= 1.15
	//marshallCompressedPubKey := elliptic.MarshalCompressed(p256, privKey.X, privKey.Y)
	//fmt.Printf("marshallCompressedPubKey: %v\n", hex.EncodeToString(marshallCompressedPubKey))
}
