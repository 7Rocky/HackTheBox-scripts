# Hack The Box. Machines. Intelligence

Machine write-up: https://7rocky.github.io/en/htb/intelligence

### `reqPdf.go`

There is a website at `intelligence.htb` that provides two PDF files named: `2020-01-01-upload.pdf` and `2020-12-15-upload.pdf`. These files contain useful information as metadata, however not enough to continue with the exploitation.

Looking at the filenames, we can try to retrieve more PDF files that have the same format (namely, `YYY-MM-DD-upload.pdf`).

For that purpose, we can write a simple Go script. First, let's write the function called `requestPdf` to request a file given a date:

```go
func requestPdf(year, month, day int) {
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
}
```

The process is simple, we generate the filename using `fmt.Sprintf` to format the year, month and day correctly. After that, we set the URL and make the GET request. If the status code is 200 (for instance 200 OK), then the file exists and we need to write the response body into a file.

To write these contents to a file, we use the function `writeToPdf`:

```go
func writeToPdf(filename string, content []byte) {
	file, err := os.Create(filename)

	if err != nil {
		panic(err)
	}

	_, err = file.Write(content)

	if err != nil {
		panic(err)
	}
}
```

This function just creates the file and writes the contents to it.

Then, we add the `main` function:

```go
func main() {
	fmt.Println("Fuzzing PDF files of the form: YYYY-MM-DD-upload.pdf")

	start := time.Now()
	year := 2020

	for month := 1; month <= 12; month++ {
		for day := 1; day <= 31; day++ {
			requestPdf(year, month, day)
		}
	}

	fmt.Printf("Found all files in %s\n", time.Since(start))
}
```

To merge all these functions and add concurrency to the program, we can make use of `go` functions and the `sync` package. The number of threads has been set to `50`. As a result, all requests ($12 \cdot 31 = 372$) are done at the same time and the downloading process will be shorter:

```console
$ go run reqPdf.go
Fuzzing PDF files of the form: YYYY-MM-DD-upload.pdf
Found 84 files in 784.6615ms
```

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to the concurrency functionality, some global variables and the imported packages.
