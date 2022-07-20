#!/usr/bin/env bash

encrypted='YXlYeDtsbD98eDtsWms5SyU='
echo "Encrypted : $encrypted"

encrypted2=$(echo $encrypted | base64 -d)
echo "Encrypted2: $encrypted2"

for i in $(seq 1 ${#encrypted2}); do
  for d in {32..126}; do
    c=$(python3 -c "print(chr($d))")

    if [ "$(./encrypt2 $c)" = ${encrypted2:i-1:1} ]; then
      encrypted1+=$c
      break
    fi
  done
done

echo "Encrypted1: $encrypted1"

for i in $(seq 1 ${#encrypted1}); do
  for d in {32..126}; do
    c=$(python3 -c "print(chr($d))")

    if [ "$(./encrypt1 $c)" = ${encrypted1:i-1:1} ]; then
      decrypted+=$c
      break
    fi
  done
done

echo "Decrypted : $decrypted"

echo Re-compute: $(./encrypt2 "$(./encrypt1 "$decrypted")" | tr -d '\n' | base64)
