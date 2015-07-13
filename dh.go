// Package dh implements "Diffie-Hellman Key Agreement Method" in RFC 2631
package dh

import (
	crand "crypto/rand"
	"crypto/sha1"
	"math/big"
	mrand "math/rand"
	"time"
)

// cryptoRandomBigInt returns a random big int.
// It returns nil if failed to get random bytes from crypto/rand.
func cryptoRandomBigInt(nb int) *big.Int {
	b := make([]byte, nb)
	_, err := crand.Read(b)
	if err != nil {
		return nil
	}
	r := new(big.Int)
	r.SetBytes(b)
	return r
}

// GeneratePQ implements [2.2.1.1. Generation of p, q] in page 8
func GeneratePQ(m, L int) (p, q *big.Int) {
	// step 1: Set m' = m/160
	mp := m/160 + 1
	// step 2: Set L' = L/160
	Lp := L/160 + 1
	// step 3: Set N' = L/1024
	Np := L/1024 + 1

	var SEED *big.Int
	for {
		// step 4: Select an arbitrary bit string SEED such that the length of SEED >= m
		SEED = cryptoRandomBigInt(m / 8)
		if SEED == nil {
			continue
		}
		// step 5: Set U = 0
		U := big.NewInt(0)
		// step 6: For i = 0 to m' - 1
		//         U = U + (SHA1[SEED + i] XOR SHA1[SEED + m' + 1]) * 2^(160*i)
		for i := 0; i < mp; i++ {
			Up := new(big.Int)
			xorPart1 := new(big.Int)
			t := new(big.Int)
			t.Add(SEED, big.NewInt(int64(i))) // SEED + i
			sha := sha1.Sum(t.Bytes())
			xorPart1.SetBytes(sha[:]) // SHA1[SEED + i] -> xorPart1
			xorPart2 := new(big.Int)
			t.Add(t, big.NewInt(int64(mp))) // SEED + i + m'
			sha = sha1.Sum(t.Bytes())
			xorPart2.SetBytes(sha[:])  // SHA1[SEED + m' + i] -> xorPart2
			Up.Xor(xorPart1, xorPart2) // XOR
			v := new(big.Int)
			v.Mul(big.NewInt(160), big.NewInt(int64(i)))
			v.Exp(big.NewInt(2), v, nil) // 2^(160*i)
			Up.Mul(Up, v)
			U.Add(U, Up) // U = U + ...
		}
		// step 5: Form q from U mod (2^m), and setting MSB and LSB to 1
		t := big.NewInt(2)
		t.Exp(t, big.NewInt(160), nil)
		U.Mod(U, t)

		q = new(big.Int)
		q.Set(U)
		q.SetBit(q, 0, 1)
		q.SetBit(q, m-1, 1)

		// step 6: test whether q is prime
		if q.ProbablyPrime(100) {
			// step 7: If q is not prime then go to step 4
			break
		}
	}
	// step 8: Let counter = 0
	counter := 0
	for {
		// step 9: Set R = seed + 2*m' + (L' * counter)
		R := new(big.Int)
		R.Set(SEED)
		t := new(big.Int)
		t.Mul(big.NewInt(2), big.NewInt(int64(mp)))
		R.Add(R, t)
		t.Mul(big.NewInt(int64(Lp)), big.NewInt(int64(counter)))
		R.Add(R, t)
		// step 10: Set V = 0
		V := big.NewInt(0)
		// step 12: For i = 0 to L'-1 do V = V + SHA1(R + i) * 2^(160*i)
		for i := 0; i < Lp; i++ {
			sha := new(big.Int)
			sha.Add(R, big.NewInt(int64(i)))
			shaBytes := sha1.Sum(sha.Bytes())
			sha.SetBytes(shaBytes[:])
			second := new(big.Int)
			second.Mul(big.NewInt(160), big.NewInt(int64(i)))
			second.Exp(big.NewInt(2), second, nil)
			sha.Mul(sha, second)
			V.Add(V, sha)
		}
		// step 13: W = V mod 2^L
		W := new(big.Int)
		t.Exp(big.NewInt(2), big.NewInt(int64(L)), nil)
		W.Mod(V, t)
		// step 14: X = W OR 2^(L-1)
		X := new(big.Int)
		X.SetBit(W, L-1, 1)
		// step 15: Set p = X - (X mod (2*q)) + 1
		p = new(big.Int)
		p.Set(X)
		t.Mul(big.NewInt(2), q)
		X.Mod(X, t)
		p.Sub(p, X)
		p.Add(p, big.NewInt(1))
		// step 16: If p > 2^(L-1), test whether p is prime
		t.Exp(big.NewInt(2), big.NewInt(int64(L-1)), nil)
		if p.Cmp(t) == 1 {
			if p.ProbablyPrime(100) {
				// step 17: If p is prime, output p, q, seed, counter and stop
				break
			}
		}
		// step 18: Set counter = counter + 1
		counter++
		// step 19: If counter < (4096 * N) then go to 8
		if counter >= 4096*Np { // !! where is N? !!
			return nil, nil
		}
	}
	return
}

// GenerateG implements [2.2.1.2. Generation of g] in page 9
func GenerateG(p, q *big.Int) (g *big.Int) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	g = new(big.Int)
	for {
		j := new(big.Int)
		j.Sub(p, big.NewInt(1))
		j.Div(j, q)
		h := new(big.Int)
		h.Rand(r, p)
		if h.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		g.Exp(h, j, p)
		if g.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}
	return
}
