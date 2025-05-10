package main

import (
	"fmt"
	"os"
	"strings"

	"math/big"

	pwn "github.com/7Rocky/pwntools"
)

type bi = big.Int

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "server.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func main() {
	io := getProcess()
	defer io.Close()

	io.SendLineAfter([]byte("[+] Option > "), []byte{'4'})
	io.RecvUntil([]byte("p = "))
	p, _ := new(bi).SetString(strings.TrimSpace(io.RecvLineS()), 10)
	io.RecvUntil([]byte("q = "))
	q, _ := new(bi).SetString(strings.TrimSpace(io.RecvLineS()), 10)
	io.RecvUntil([]byte("g = "))
	g, _ := new(bi).SetString(strings.TrimSpace(io.RecvLineS()), 10)
	io.SendLineAfter([]byte("[+] Test user log (y/n): "), []byte{'y'})
	io.SendLineAfter([]byte("Enter your password : "), []byte("5up3r_53cur3_P45sw0r6"))
	io.RecvUntil([]byte{'['})

	for range 6 {
		io.RecvUntil([]byte("(("))
	}

	r, _ := new(bi).SetString(io.RecvUntilS([]byte(", "), true), 10)
	s, _ := new(bi).SetString(io.RecvUntilS([]byte("), '"), true), 10)
	h, _ := new(bi).SetString(io.RecvUntilS([]byte{'\''}, true), 16)

	k := int64(65500)

	for gkp := new(bi).Exp(g, new(bi).SetInt64(k), p); r.Cmp(new(bi).Mod(gkp, q)) != 0; k++ {
		gkp.Mod(gkp.Mul(gkp, g), p)
	}

	x := new(bi).Mod(new(bi).Mul(new(bi).Sub(new(bi).Mul(s, new(bi).SetInt64(k)), h), new(bi).ModInverse(r, q)), q)

	io.SendLineAfter([]byte("[+] Option > "), []byte{'3'})
	io.SendLineAfter([]byte("Please enter the username that stored the message: "), []byte("ElGamalSux"))
	io.SendLineAfter([]byte("Please enter the message's request id: "), []byte{'3'})
	io.SendLineAfter([]byte("Please enter the message's nonce value: "), fmt.Appendf(nil, "%d", k))
	io.SendLineAfter([]byte("[+] Please enter the private key: "), []byte(x.String()))

	io.RecvUntil([]byte("[+] Here is your super secret message: "))
	io.RecvUntil([]byte("b'"))
	pwn.Success(io.RecvUntilS([]byte{'\''}, true))
}
