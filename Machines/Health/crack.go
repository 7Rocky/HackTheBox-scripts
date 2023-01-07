//usr/bin/env go run $0 $@; exit $?

package main

import (
	"bufio"
	"fmt"
	"os"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// EncodePassword encodes password using PBKDF2 SHA256 with given salt.
func EncodePassword(password, salt string) string {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return fmt.Sprintf("%x", newPasswd)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run crack.go <wordlist> <hash> <salt>")
		os.Exit(1)
	}

	hash, salt := os.Args[2], os.Args[3]
	file, err := os.Open(os.Args[1])

	if err != nil {
		fmt.Println("File not found")
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := scanner.Text()

		if EncodePassword(password, salt) == hash {
			fmt.Println("[+] Craked:", password)
			break
		}
	}
}
