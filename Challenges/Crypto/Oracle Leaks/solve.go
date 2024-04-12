package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"math/big"
)

type Conn struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

var (
	conn Conn

	e = big.NewInt(65537)

	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func (conn *Conn) RecvUntil(pattern []byte, drop ...bool) []byte {
	var recv []byte
	buf := make([]byte, 1)

	for !bytes.HasSuffix(recv, pattern) {
		n, err := conn.stdout.Read(buf)

		if err != nil {
			panic(err)
		}

		if n == 1 {
			recv = append(recv, buf[0])
		}
	}

	if len(drop) == 1 && drop[0] {
		return bytes.ReplaceAll(recv, pattern, []byte(""))
	}

	return recv
}

func (conn *Conn) RecvLine() []byte {
	return conn.RecvUntil([]byte("\n"))
}

func (conn *Conn) Send(data []byte) int {
	n, err := conn.stdin.Write(data)

	if err != nil {
		panic(err)
	}

	return n
}

func (conn *Conn) SendLine(data []byte) int {
	return conn.Send(append(data, '\n'))
}

func (conn *Conn) SendLineAfter(pattern, data []byte) []byte {
	recv := conn.RecvUntil(pattern)
	conn.SendLine(data)
	return recv
}

func oracle(x, c, n *big.Int) bool {
	test := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(x, e, n), c), n)

	conn.SendLineAfter([]byte("> "), []byte("3"))
	conn.SendLineAfter([]byte("> "), []byte(hex(test)))
	conn.RecvUntil([]byte("Length: "))

	return string(conn.RecvLine()) == "128\n"
}

func fromhex(hex string) *big.Int {
	x, _ := new(big.Int).SetString(hex, 16)
	return x
}

func hex(x *big.Int) string {
	hex := x.Text(16)

	if len(hex)%2 == 1 {
		return "0" + hex
	}

	return hex
}

func divceil(a, b *big.Int) *big.Int {
	quo, rem := new(big.Int).QuoRem(a, b, new(big.Int))

	if rem.Cmp(zero) > 0 {
		quo.Add(quo, one)
	}

	return quo
}

func main() {
	if len(os.Args) == 1 {
		cmd := exec.Command("python3", "chall.py")
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		conn = Conn{stdin, stdout}
		cmd.Start()
	} else {
		c, err := net.Dial("tcp", os.Args[1])

		if err != nil {
			panic(err)
		}

		defer c.Close()
		stdin := io.WriteCloser(c)
		stdout := io.ReadCloser(c)
		conn = Conn{stdin, stdout}
	}

	conn.SendLineAfter([]byte("> "), []byte("1"))
	conn.RecvUntil([]byte("('"))
	n := fromhex(string(conn.RecvUntil([]byte("'"), true)))

	conn.SendLineAfter([]byte("> "), []byte("2"))
	conn.RecvUntil([]byte("Encrypted text: "))
	c := fromhex(strings.Trim(string(conn.RecvLine()), "\n"))

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
	mmin := divceil(n, f2)
	mmax := new(big.Int).Div(nB, f2)
	BB := new(big.Int).Mul(two, B)
	diff := new(big.Int).Sub(mmax, mmin)

	for diff.Sub(mmax, mmin).Cmp(zero) > 0 {
		ftmp := new(big.Int).Div(BB, diff)
		ftmpmmin := new(big.Int).Mul(ftmp, mmin)
		i := new(big.Int).Div(ftmpmmin, n)
		iN := new(big.Int).Mul(i, n)
		iNB := new(big.Int).Add(iN, B)
		f3 := divceil(iN, mmin)

		if oracle(f3, c, n) {
			mmin = divceil(iNB, f3)
		} else {
			mmax.Div(iNB, f3)
		}
	}

	splitted := strings.Split(string(mmin.Bytes()), "\x00")
	flag := splitted[len(splitted)-1]
	fmt.Println(flag)
}
