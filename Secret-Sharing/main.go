package main

import (
	"fmt"
	"github.com/SSSaaS/sssa-golang"
	"os"
)

// sharmir(t,w)：准备w把钥匙，至少要t把钥匙才能开启
func main() {

	secret := "0y10VAfmyH7GLQY6QccCSLKJi8iFgpcSBTLyYOGbiYPqOpStAf1OYuzEBzZR"
	w := 5
	t := 3
	secretShares, err := sssa.Create(t, w, secret)
	if err != nil {
		fmt.Printf("Create err: %v\n", err)
		os.Exit(-1)
	}
	fmt.Printf("secretShares: %v\n", secretShares)

	testShares := []string{
		secretShares[0],
		secretShares[1],
		secretShares[2],
	}
	combined, err := sssa.Combine(testShares)
	if err != nil {
		fmt.Printf("Combine err: %v\n", err)
		os.Exit(-1)
	}
	if combined != secret {
		fmt.Printf("Fatal: combining returned invalid data\n")
		os.Exit(-1)
	}
}
