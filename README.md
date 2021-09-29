# ogvt

A [pledge(2)](https://man.openbsd.org/pledge) and [unveil(2)](https://man.openbsd.org/unvile)'d tool for verifying GnuPG signatures.

[![builds.sr.ht status](https://builds.sr.ht/~qbit/ogvt.svg)](https://builds.sr.ht/~qbit/ogvt?)

## Success
```
./ogvt -file test/uptime.txt  -sig test/uptime.txt.asc -pub test/adent.pub
"Arthur Dent <adent@in.space.time>" (85A37DE03BBE9A3019A7E3A43BC546AF2E6705B7)
Signature OK.
```

## Failure
```
./ogvt -file test/uptime.txt.bad -sig test/uptime.txt.asc -pub test/adent.pub
openpgp: invalid signature: hash tag doesn't match
```
