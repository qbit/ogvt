#!/bin/sh

set -e

mandoc -T lint ./ogvt.1
go build
printf "Testing detached armor (asc)\t\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.asc -pub test/adent.pub >/dev/null && echo "OK" || echo "FAIL"

printf "Testing detached non-armor (gpg)\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.gpg -pub test/adent.pub >/dev/null && echo "OK" || echo "FAIL"

printf "Testing detached non-armor (sig)\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.sig -pub test/adent.pub >/dev/null && echo "OK" || echo "FAIL"

printf "Testing just having a sig (nofile)\t"
./ogvt -sig test/uptime.txt.sig -pub test/adent.pub >/dev/null && echo "OK" || echo "FAIL"

printf "Testing clearsig file (clear-asc)\t"
./ogvt -sig test/uptime2.txt.asc -pub test/adent.pub >/dev/null && echo "OK" || echo "FAIL"

printf "Testing bad sig file\t\t\t"
./ogvt -file test/uptime.txt -sig test/bad.sig -pub test/adent.pub >/dev/null && echo "FAIL" || echo "OK"

printf "Testing empty file\t\t\t"
./ogvt -file test/uptime.txt -sig /dev/null -pub test/adent.pub >/dev/null && echo "FAIL" || echo "OK"

