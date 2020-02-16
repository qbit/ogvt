#!/bin/sh

set -e

mandoc -T lint ./ogvt.1
go build
printf "Testing detached armor (asc)\t\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.asc  -pub test/adent.pub >/dev/null && echo "OK"
printf "Testing detached non-armor (gpg)\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.gpg  -pub test/adent.pub >/dev/null && echo "OK"
printf "Testing detached non-armor (sig)\t"
./ogvt -file test/uptime.txt -sig test/uptime.txt.sig  -pub test/adent.pub >/dev/null && echo "OK"
printf "Testing bad sig file\t\t\t"
./ogvt -file test/uptime.txt -sig test/bad.sig  -pub test/adent.pub >/dev/null || echo "OK"
printf "Testing empty file\t\t\t"
./ogvt -file test/uptime.txt -sig /dev/null  -pub test/adent.pub >/dev/null || echo "OK"
