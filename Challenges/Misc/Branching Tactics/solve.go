package main

import (
	"os"
	"slices"
	"strconv"
	"strings"

	pwn "github.com/7Rocky/gopwntools"
)

type path struct {
	node int
	path []int
}

func bfs(s, d int, edges map[int][]int) []int {
	queue := []path{{node: s, path: []int{s}}}
	visited := map[int]bool{}

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		visited[n.node] = true

		if n.node == d {
			return n.path
		}

		for _, v := range edges[n.node] {
			if !visited[v] {
				queue = append(queue, path{node: v, path: slices.Concat(n.path, []int{v})})
			}
		}
	}

	return []int{}
}

func solve(s, d, e int, edges map[int][]int) int {
	path := bfs(s, d, edges)

	if e >= len(path) {
		return d
	} else {
		return path[e]
	}
}

func main() {
	hostPort := strings.Split(os.Args[1], ":")
	io := pwn.Remote(hostPort[0], hostPort[1])
	defer io.Close()

	prog := pwn.Progress("Round")

	for range 100 {
		io.RecvUntil([]byte("Test"))
		prog.Status(strings.TrimSpace(io.RecvLineS()))

		n, _ := strconv.Atoi(strings.TrimSpace(io.RecvLineS()))
		edges := map[int][]int{}

		for i := 0; i < n-1; i++ {
			e1, _ := strconv.Atoi(strings.TrimSpace(io.RecvUntilS([]byte{' '})))
			e2, _ := strconv.Atoi(strings.TrimSpace(io.RecvLineS()))

			edges[e1] = append(edges[e1], e2)
			edges[e2] = append(edges[e2], e1)
		}

		m, _ := strconv.Atoi(strings.TrimSpace(io.RecvLineS()))

		for i := 0; i < m; i++ {
			s, _ := strconv.Atoi(strings.TrimSpace(io.RecvUntilS([]byte{' '})))
			d, _ := strconv.Atoi(strings.TrimSpace(io.RecvUntilS([]byte{' '})))
			e, _ := strconv.Atoi(strings.TrimSpace(io.RecvLineS()))

			res := solve(s, d, e, edges)
			io.SendLine([]byte(strconv.Itoa(res)))
		}
	}

	prog.Success("100/100")

	io.RecvUntil([]byte("HTB{"))
	pwn.Success("HTB{" + io.RecvLineS())
}
