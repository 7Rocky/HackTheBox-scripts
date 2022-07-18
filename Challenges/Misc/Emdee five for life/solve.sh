#!/usr/bin/env bash

host=$1

if [ -z "$host" ]; then
	echo "bash $0 <ip:port>"
	exit 1
fi

res=$(curl -si $host)
cookie=$(grep -oE 'Cookie: .*?;' <<< $res | tr -d ';')

string=$(grep -oE "<h3 align='center'>.*?</h3>" <<< $res)
md5=$(echo -n ${string:19:20} | md5sum | awk '{ print $1 }')

curl -H "$cookie" -sd hash=$md5 $host | grep -oE 'HTB{.*?}'
