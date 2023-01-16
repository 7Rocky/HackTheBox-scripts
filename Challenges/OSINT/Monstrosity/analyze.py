#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np
import requests

from pwn import log, os, sys


def main():
    token = os.environ.get("BEARER_TOKEN")

    if len(sys.argv) != 2 or not token:
        print(f'[!] Usage: python3 {sys.argv[0]} <user_id>')
        print("[!] Set variable: `export BEARER_TOKEN='<your_bearer_token>'`")
        exit(1)

    user_id = int(sys.argv[1])
    data = []

    r = requests.get(f'https://api.twitter.com/2/users/{user_id}/tweets',
                     params={'tweet.fields': 'geo', 'max_results': 100},
                     headers={'Authorization': f'Bearer {token}'},
    )

    prog = log.progress('Tweets')
    
    while (next_token := r.json().get('meta', {}).get('next_token', '')):
        data += r.json()['data']

        r = requests.get(f'https://api.twitter.com/2/users/{user_id}/tweets',
                         params={'tweet.fields': 'geo', 'max_results': 100, 'pagination_token': next_token},
                         headers={'Authorization': f'Bearer {token}'},
        )

        prog.status(f'{len(data)} / 3000')

    prog.success(f'{len(data)} / 3000')

    data = filter(lambda d: d.get('geo', False), data)
    data = list(map(lambda d: d['geo']['coordinates']['coordinates'], data))

    x_list = list(map(lambda d: d[0], data))
    y_list = list(map(lambda d: d[1], data))

    log.success('Coordinates:\n')
    print('\n'.join(map(lambda d: str(d)[1:-1], data)))

    plt.xlim(-200, 200)
    plt.ylim(-200, 200)
    plt.grid()

    plt.plot(x_list, y_list, marker='o', color='r', ls='')
    plt.show()


if __name__ == "__main__":
    main()
