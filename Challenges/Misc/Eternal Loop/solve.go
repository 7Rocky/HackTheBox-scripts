package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"os/exec"
)

func main() {
	r := regexp.MustCompile(`(skipping|inflating): (\d+)\.zip`)
	output, _ := exec.Command("unzip", "-P", "xxx", "Eternal Loop.zip").CombinedOutput()

	password := r.FindStringSubmatch(string(output))[2]
	newPassword := "hackthebox"
	stage := 1

	exec.Command("unzip", "-P", newPassword, "Eternal Loop.zip").Run()

	for {
		output, _ := exec.Command("unzip", "-P", newPassword, password+".zip").CombinedOutput()
		matches := r.FindStringSubmatch(string(output))

		if len(matches) == 0 {
			break
		}

		newPassword = matches[2]

		err := exec.Command("unzip", "-P", newPassword, password+".zip").Run()

		if err != nil {
			exec.Command("rm", "-r", newPassword+".zip").Run()

			if exec.Command("unzip", "-P", newPassword, password+".zip").Run() != nil {
				break
			}
		}

		exec.Command("rm", "-r", password+".zip").Run()

		password = newPassword
		fmt.Printf("[+] Stage: %d\r", stage)
		stage++
	}

	fmt.Println()

	r = regexp.MustCompile(`(skipping|inflating): (\w+)`)

	output, _ = exec.Command("unzip", "-P", newPassword, password+".zip").CombinedOutput()
	filename := r.FindStringSubmatch(string(output))[2]

	fmt.Println("[*] Starting brute force attack")

	if len(os.Args) != 2 {
		fmt.Println("[!] No wordlist specified")
		os.Exit(1)
	}

	output, _ = exec.Command("fcrackzip", "-uDp", os.Args[1], password+".zip").CombinedOutput()
	newPassword = strings.Trim(string(output[len("PASSWORD FOUND!!!!: pw == ")+1:]), " \n")
	fmt.Println("[+] Found password: " + newPassword)

	exec.Command("unzip", "-P", newPassword, password+".zip").Run()
	exec.Command("rm", "-r", password+".zip").Run()

	fmt.Printf("[*] Running `strings` on file '%s'\n", filename)
	res, _ := exec.Command("strings", filename).CombinedOutput()
	r = regexp.MustCompile(`(HTB\{.*\})`)
	flag := r.FindStringSubmatch(string(res))[1]

	fmt.Println("[+] Flag: " + flag)
}
