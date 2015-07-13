# diffie-hellman
Package dh implements "Diffie-Hellman Key Agreement Method" (RFC 2631) in go programming language.

This project provides two functions.
- GeneratePQ: func GeneratePQ(m, L int) (p, q *big.Int)
- GenerateG : func GenerateG(p, q *big.Int) (g *big.Int)

