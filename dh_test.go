package dh

import (
	"fmt"
	"math/big"
	"testing"
)

func ExampleCryptoRandomBitInt() {
	ri := cryptoRandomBigInt(100)
	fmt.Printf("Invalid generation of a random big integer: %v (%v bits)\n", ri, ri.BitLen())
	ri = cryptoRandomBigInt(200)
	fmt.Printf("Invalid generation of a random big integer: %v (%v bits)\n", ri, ri.BitLen())
}

func TestDiffieHellman(t *testing.T) {
	p, q := GeneratePQ(160, 512)
	g := GenerateG(p, q)

	xa := cryptoRandomBigInt(256)
	xb := cryptoRandomBigInt(256)

	ya := new(big.Int)
	yb := new(big.Int)
	ya.Exp(g, xa, p)
	yb.Exp(g, xb, p)

	ZZa := new(big.Int)
	ZZb := new(big.Int)
	ZZa.Exp(yb, xa, p)
	ZZb.Exp(ya, xb, p)

	if ZZa.Cmp(ZZb) != 0 {
		t.Errorf("Key mismatched:\n\tp = %v\nq = %v\ng = %v\nxa = %v\nxb = %v\nya = %v\nyb = %v\nZZa = %v\nZZb = %v", p, q, g, xa, xb, ya, yb, ZZa, ZZb)
	}
}
