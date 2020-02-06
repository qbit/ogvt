# ogvt

A [pledge(2)](https://man.openbsd.org/pledge) and [unveil(2)](https://man.openbsd.org/unvile)'d tool for verifying GnuPG signatures.


## Success
```
./ogvt -file test/uptime.txt  -sig test/uptime.txt.asc -pub test/adent.pub
Arthur Dent <adent@in.space.time>
Signature OK.
```

## Failure
```
./ogvt -file test/uptime.txt.bad -sig test/uptime.txt.asc -pub test/adent.pub
openpgp: invalid signature: hash tag doesn't match
```
