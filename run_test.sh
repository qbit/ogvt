#!/bin/sh

set -e

mandoc -T lint ./ogvt.1
go build
echo "Testing detached armor: asc"
./ogvt -file test/uptime.txt -sig test/uptime.txt.asc  -pub test/adent.pub
echo "Testing detached non-armor: gpg"
./ogvt -file test/uptime.txt -sig test/uptime.txt.gpg  -pub test/adent.pub
echo "Testing detached non-armor: sig"
./ogvt -file test/uptime.txt -sig test/uptime.txt.sig  -pub test/adent.pub
