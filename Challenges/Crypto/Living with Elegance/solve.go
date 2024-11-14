package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	pwn "github.com/7Rocky/gopwntools"
)

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "server.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func getEncryption(index int) int {
	io.SendLineAfter([]byte("Specify the index of the bit you want to get an encryption for : "), []byte(strconv.Itoa(index)))
	io.RecvUntil([]byte("b = "))
	c, _ := strconv.Atoi(strings.TrimSpace(io.RecvLineS()))
	return c
}

var io *pwn.Conn

func main() {
	io = getProcess()
	defer io.Close()

	io.SendLineAfter([]byte("Specify the index of the bit you want to get an encryption for : "), []byte("10000"))
	io.RecvUntil([]byte("The index must lie in the interval [0, "))
	bitLength, _ := strconv.Atoi(io.RecvUntilS([]byte{']'}, true))
	bitLength++

	bits := make([]int, bitLength)
	prog := pwn.Progress("Bits")

	for i := 0; i < bitLength; i++ {
		prog.Status(fmt.Sprintf("%d / %d", i+1, bitLength))

		for range 30 {
			c := getEncryption(i)

			if c < 0 || 256 < c {
				bits[i] = 1
				break
			}
		}
	}

	prog.Success(fmt.Sprintf("%[1]d / %[1]d", bitLength))

	for len(bits)%8 != 0 {
		bits = append([]int{0}, bits...)
	}

	flag := make([]byte, len(bits)/8)

	for i := 0; i < bitLength; i += 8 {
		for j, v := range bits[i : i+8] {
			flag[i/8] |= byte(v << (7 - j))
		}
	}

	pwn.Success(string(flag))
}
