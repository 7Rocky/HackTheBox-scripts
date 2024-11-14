package main

import (
	"bytes"
	"os"
	"strings"

	"crypto/sha256"

	pwn "github.com/7Rocky/gopwntools"
)

func getProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "server.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func buyHint(inp []byte) []byte {
	var outs []string

	for range 4 {
		io.SendLineAfter([]byte("Option: "), []byte{'2'})
		io.SendLineAfter([]byte("Enter your input in hex :: "), []byte(pwn.Hex(inp)))
		io.RecvUntil([]byte("Your output is :: "))
		out := strings.TrimSpace(io.RecvLineS())
		outs = append(outs, out)
	}

	counter := map[string]int{}

	for _, out := range outs {
		counter[out]++
	}

	var max string
	maxCount := 0

	for out, count := range counter {
		if count > maxCount {
			max = out
		}
	}

	return pwn.UnHex(max)
}

var io *pwn.Conn

func main() {
	io = getProcess()
	defer io.Close()

	message := []byte("Improving on the security of SHA is easy")

	hint := buyHint([]byte{})
	hashHashKeyMessage := hint[:32]

	hint = buyHint(message)
	hashKeyMessage := hint[32:]

	h := sha256.Sum256(hashKeyMessage)

	if !bytes.Equal(hashHashKeyMessage, h[:]) {
		pwn.Error("Try again")
	}

	h = sha256.Sum256(append(hashKeyMessage, message...))

	if !bytes.Equal(h[:], hint[:32]) {
		pwn.Error("Try again")
	}

	for range (500 - 20) / 5 {
		io.SendLineAfter([]byte("Option: "), []byte{'3'})
		io.RecvUntil([]byte("I used input "))
		inp := pwn.UnHex(strings.TrimSpace(io.RecvLineS()))
		io.RecvUntil([]byte("I got output "))
		out := pwn.UnHex(strings.TrimSpace(io.RecvLineS()))

		res := []byte{'1'}
		h = sha256.Sum256(append(hashKeyMessage, inp...))

		if bytes.Equal(out[:32], h[:]) {
			res[0] = '0'
		}

		io.SendLineAfter([]byte("Was the output from my hash or random? (Enter 0 or 1 respectively) :: "), res)

		if !strings.Contains(io.RecvLineS(), "Lucky you!") {
			pwn.Error("Failed")
		}
	}

	io.SendLineAfter([]byte("Option: "), []byte{'1'})
	msg := io.RecvLineS()
	pwn.Success(msg[strings.Index(msg, "HTB"):])
}
