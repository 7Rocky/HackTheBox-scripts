package main

import (
	"bytes"
	"os"
	"strings"

	"crypto/sha256"

	pwn "github.com/7Rocky/pwntools"
)

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "server.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func sendHash(io *pwn.Conn, msg []byte) string {
	io.SendLineAfter([]byte("> "), []byte{'1'})
	io.SendLineAfter([]byte("Enter your message: "), msg)
	io.RecvUntil([]byte("Hash: "))
	return strings.TrimSpace(io.RecvLineS())
}

func main() {
	io := getProcess()
	defer io.Close()

	var flag []byte
	prog := pwn.Progress("Flag")

	for !bytes.ContainsRune(flag, '}') {
		prog.Status(string(flag))
		h := sendHash(io, bytes.Repeat([]byte{'\x00'}, len(flag)+1))

		for c := byte(0x20); c < 0x7f; c++ {
			s := sha256.Sum256(append(flag, c))

			if pwn.Hex(s[:]) == h {
				flag = append(flag, c)
				break
			}
		}
	}

	prog.Success(string(flag))
}
