package main

import (
	"os"
	"strconv"
	"strings"

	pwn "github.com/7Rocky/gopwntools"
)

func findSumSign(op string) int {
	for i, t := range op {
		if t == '+' {
			return i
		}
	}

	return -1
}

func getLastNumber(op string) (int, int) {
	terms := strings.Split(op, " ")
	number, _ := strconv.Atoi(terms[len(terms)-1])

	return number, len(terms[len(terms)-1])
}

func getFirstNumber(op string) (int, int) {
	terms := strings.Split(op, " ")
	number, _ := strconv.Atoi(terms[0])

	return number, len(terms[0])
}

func evaluateSums(op string) string {
	for strings.Count(op, "+") != 0 {
		sum := findSumSign(op)

		num1, digits1 := getLastNumber(op[:sum-1])
		num2, digits2 := getFirstNumber(op[sum+2:])

		partial := num1 + num2

		op = op[:sum-1-digits1] + strconv.Itoa(partial) + op[sum+2+digits2:]
	}

	return op
}

func evaluateArithmetic(op string) int {
	op = evaluateSums(op)

	terms := strings.Split(op, " ")
	result, _ := strconv.Atoi(terms[0])

	for i := 1; i < len(terms); i += 2 {
		if terms[i] == "*" {
			num, _ := strconv.Atoi(terms[i+1])
			result *= num
		}
	}

	return result
}

func findMostInnerParentheses(op string) (int, int) {
	opening, closing := -1, -1

	for i, t := range op {
		if t == '(' {
			opening = i
		}

		if t == ')' {
			closing = i
			break
		}
	}

	return opening, closing
}

func evaluate(op string) int {
	for strings.Count(op, "(") > 0 {
		opening, closing := findMostInnerParentheses(op)

		partial := evaluateArithmetic(op[opening+1 : closing])

		op = op[:opening] + strconv.Itoa(partial) + op[closing+1:]
	}

	return evaluateArithmetic(op)
}

func main() {
	hostPort := strings.Split(os.Args[1], ":")
	io := pwn.Remote(hostPort[0], hostPort[1])
	defer io.Close()

	prog := pwn.Progress("Round")

	for round := 0; round < 500; round++ {
		prog.Status(strconv.Itoa(round+1) + " / 500")

		io.RecvUntil([]byte("]: "))
		operation := io.RecvLineS()
		operation = strings.Trim(operation, "= ?\n")

		result := evaluate(operation)
		io.SendLineAfter([]byte("> "), []byte(strconv.Itoa(result)))
	}

	prog.Success("500 / 500")
	pwn.Success(io.RecvLineS())
}
