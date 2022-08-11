#!/usr/bin/env python3

from pwn import log, remote, sys

movements = {
    (0, 1): 'R',
    (0, -1): 'L',
    (1, 0): 'D',
}

final_path = ''


def dfs(root, maze, visited, path=''):
    global final_path

    if -1 in root or len(maze) <= root[0] or len(maze[0]) <= root[1]:
        return

    if maze[root[0]][root[1]] == '💎' and final_path == '':
        final_path = path

    visited.add(root)

    for movement in [(1, 0), (0, -1), (0, 1)]:
        node = (root[0] + movement[0], root[1] + movement[1])

        if -1 in node or len(maze) <= node[0] or len(maze[0]) <= node[1]:
            continue

        if node not in visited and maze[node[0]][node[1]] != '☠️':
            dfs(node, maze, visited.copy(), path + movements[movement])


def main():
    global final_path

    if len(sys.argv) != 2:
        log.warning(f'Usage: python3 {sys.argv[0]} <host:port>')
        exit(1)

    host, port = sys.argv[1].split(':')
    r = remote(host, int(port))

    r.sendlineafter(b'> ', b'2')
    prog = log.progress('Round')

    for round in range(500):
        prog.status(str(round + 1))
        r.recvline()

        maze = list(map(
            lambda s: s.split()[1:-1],
            r.recvuntil(b'\n\n').strip().decode().splitlines()
        ))[1:-1]

        j = maze[0].index('🤖')
        dfs((0, j), maze, {(0, j)})

        r.sendlineafter(b'> ', final_path.encode())
        final_path = ''
        r.recvline()

    prog.success(str(round + 1))
    print(r.recv().decode())
    r.close()


if __name__ == '__main__':
    main()
