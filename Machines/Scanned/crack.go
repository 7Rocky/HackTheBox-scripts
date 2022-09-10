//usr/bin/env go run $0 $@; exit $?

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"crypto/md5"
)

func crack(salt, password string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(salt+password)))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run crack.go <wordlist> <hash>")
		os.Exit(1)
	}

	full_hash := os.Args[2]
	splitted_hash := strings.Split(full_hash, "$")
	alg, salt, hash := splitted_hash[0], splitted_hash[1], splitted_hash[2]

	fmt.Printf("[*] Algorithm: \t %s\n", alg)
	fmt.Printf("[*] Salt: \t %s\n", salt)
	fmt.Printf("[*] Hash: \t %s\n\n", hash)

	file, err := os.Open(os.Args[1])

	if err != nil {
		fmt.Printf("File '%s' not found\n", os.Args[1])
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := scanner.Text()

		if crack(salt, password) == hash {
			fmt.Println("[+] Cracked:", password)
			break
		}
	}
}
