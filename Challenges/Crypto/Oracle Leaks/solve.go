package main

import (
	"os"
	"strings"

	"math/big"

	pwn "github.com/7Rocky/gopwntools"
)

var (
	io *pwn.Conn

	e = big.NewInt(65537)

	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "chall.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func divCeil(a, b *big.Int) *big.Int {
	quo, rem := new(big.Int).QuoRem(a, b, new(big.Int))

	if rem.Cmp(zero) > 0 {
		quo.Add(quo, one)
	}

	return quo
}

func oracle(x, c, n *big.Int) bool {
	test := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(x, e, n), c), n)

	io.SendLineAfter([]byte("> "), []byte{'3'})
	io.SendLineAfter([]byte("> "), []byte(pwn.Hex(test.Bytes())))

	return strings.Contains(io.RecvLineContainsS([]byte("Length: ")), "128")
}

func main() {
	io = getProcess()
	defer io.Close()

	io.SendLineAfter([]byte("> "), []byte{'1'})
	io.RecvUntil([]byte("('"))
	n, _ := new(big.Int).SetString(io.RecvUntilS([]byte("'"), true), 16)

	io.SendLineAfter([]byte("> "), []byte{'2'})
	io.RecvUntil([]byte("Encrypted text: "))
	c, _ := new(big.Int).SetString(strings.TrimSpace(io.RecvLineS()), 16)

	k := n.BitLen() / 8
	B := new(big.Int).Exp(two, big.NewInt(int64(8*(k-1))), nil)

	// Step 1
	f1 := new(big.Int).Set(one)

	for !oracle(f1.Mul(two, f1), c, n) {
	}

	// Step 2
	f12 := new(big.Int).Div(f1, two)
	nB := new(big.Int).Add(n, B)
	nBB := new(big.Int).Div(nB, B)
	f2 := new(big.Int).Mul(nBB, f12)

	for oracle(f2.Add(f2, f12), c, n) {
	}

	// Step 3
	mmin := divCeil(n, f2)
	mmax := new(big.Int).Div(nB, f2)
	BB := new(big.Int).Mul(two, B)
	diff := new(big.Int).Sub(mmax, mmin)

	for diff.Sub(mmax, mmin).Cmp(zero) > 0 {
		ftmp := new(big.Int).Div(BB, diff)
		ftmpmmin := new(big.Int).Mul(ftmp, mmin)
		i := new(big.Int).Div(ftmpmmin, n)
		iN := new(big.Int).Mul(i, n)
		iNB := new(big.Int).Add(iN, B)
		f3 := divCeil(iN, mmin)

		if oracle(f3, c, n) {
			mmin = divCeil(iNB, f3)
		} else {
			mmax.Div(iNB, f3)
		}
	}

	splitted := strings.Split(string(mmin.Bytes()), "\x00")
	flag := splitted[len(splitted)-1]
	pwn.Success("Flag: " + flag)
}
