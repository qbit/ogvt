package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/sys/unix"
)

func verify(pubKey, file, sig io.Reader) (*openpgp.Entity, error) {
	kr, err := openpgp.ReadArmoredKeyRing(pubKey)
	if err != nil {
		return nil, err
	}

	return openpgp.CheckArmoredDetachedSignature(kr, file, sig)
}

func open(path string) io.Reader {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return f
}

func main() {
	var sig, file, pub string
	flag.StringVar(&sig, "sig", "", "path to signature file")
	flag.StringVar(&file, "file", "", "path to file")
	flag.StringVar(&pub, "pub", "", "path to pub file")
	flag.Parse()

	unix.PledgePromises("stdio tty unveil rpath")

	unix.Unveil(sig, "r")
	unix.Unveil(file, "r")
	unix.Unveil(pub, "r")
	unix.UnveilBlock()

	ent, err := verify(open(pub), open(file), open(sig))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, id := range ent.Identities {
		fmt.Printf("%s\n", id.Name)
	}
	fmt.Println("Signature OK.")
}
