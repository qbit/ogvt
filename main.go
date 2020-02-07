package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

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

	pledge("stdio tty unveil rpath")

	unveil(sig, "r")
	unveil(file, "r")
	unveil(pub, "r")
	unveilBlock()

	kr, err := openpgp.ReadArmoredKeyRing(open(pub))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var ent *openpgp.Entity

	switch {
	case strings.HasSuffix(sig, ".sig"):
	case strings.HasSuffix(sig, ".gpg"):
		ent, err = openpgp.CheckDetachedSignature(kr, open(file), open(sig))
	case strings.HasSuffix(sig, ".asc"):
		ent, err = openpgp.CheckArmoredDetachedSignature(kr, open(file), open(sig))
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, id := range ent.Identities {
		fmt.Printf("%s\n", id.Name)
	}
	fmt.Println("Signature OK.")
}
