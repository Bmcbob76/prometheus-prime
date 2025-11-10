#!/bin/bash

path=$1

openssl req -new -x509 -keyout "${path}/empire-priv.key" -out "${path}/empire-chain.pem" -days 365 -nodes -subj "/C=US" >/dev/null 2>&1

echo -e "\x1b[1;34m[*] Certificate written to ${path}/empire-chain.pem\x1b[0m"
echo -e "\x1b[1;34m[*] Private key written to ${path}/empire-priv.key\x1b[0m"
