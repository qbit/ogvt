# ogvt

aka: OpenBSD Gnupg Verification Tool

A [pledge(2)](https://man.openbsd.org/pledge) and [unveil(2)](https://man.openbsd.org/unvile)'d tool for verifying GnuPG signatures.


## Success
```
./ogvt -file test/uptime.txt -sig test/uptime.txt.asc -pub test/abieber.pub
```

## Failure
```
./ogvt -file test/uptime.txt.bad -sig test/uptime.txt.asc -pub test/abieber.pub
```
