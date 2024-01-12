from pwn import random, re, remote, sys, time


def main():
    ip, port = sys.argv[1].split(':')
    flag = win_lotto(ip, port)

    print()
    print(flag)


def win_lotto(ip, port):
    r = remote(ip, port)
    now = int(time.time()) - 2

    out = r.recvuntil(b'numbers: ').decode()
    extraction, _ = re.findall(r'EXTRACTION: ((\d+ ){5})', out)[0]

    ext, dt = '', 0

    while ext != extraction.strip():
        ext, sol = handle(now + dt)
        dt += 1

        if dt > 10:
            print('Not found...')
            sys.exit(1)

    r.sendline(sol.encode())

    flag = re.findall(r'HTB\{.*?\}', r.recvall().decode('utf-8'))[0]

    r.close()

    return flag


def handle(seed):
    random.seed(seed)

    def gen():
        numbers = []

        while len(numbers) < 5:
            r = random.randint(1, 90)

            if r not in numbers:
                numbers.append(r)

        return numbers

    extracted, solution = gen(), gen()

    return ' '.join(map(str, extracted)), ' '.join(map(str, solution))


if __name__ == '__main__':
    main()
