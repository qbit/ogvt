package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"suah.dev/protect"
)

func errExit(err error) {
	if err != nil {
		if err == io.EOF {
			fmt.Println("invalid signature file")
		} else {
			fmt.Println(err)
		}
		os.Exit(1)
	}
}

func main() {
	var sig, file, pub string
	flag.StringVar(&sig, "sig", "", "path to signature file")
	flag.StringVar(&file, "file", "", "path to file")
	flag.StringVar(&pub, "pub", "", "path to pub file")
	flag.Parse()

	_ = protect.Pledge("stdio tty unveil rpath")

	_ = protect.Unveil(sig, "r")
	_ = protect.Unveil(file, "r")
	_ = protect.Unveil(pub, "r")
	_ = protect.UnveilBlock()

	if sig != "" && file == "" {
		// Check for a 'file' with the .sig extensions removed
		bn := strings.TrimSuffix(sig, filepath.Ext(sig))
		if _, err := os.Stat(bn); err == nil {
			file = bn
		}
	}

	fPub, err := os.Open(pub)
	errExit(err)

	fFile, err := os.Open(file)
	errExit(err)

	fSig, err := os.Open(sig)
	errExit(err)

	defer fPub.Close()
	defer fSig.Close()
	defer fFile.Close()

	kr, err := openpgp.ReadArmoredKeyRing(fPub)
	if err != nil {
		fmt.Printf("Can't parse public key '%s'\n%s", pub, err)
		os.Exit(1)
	}

	var ent *openpgp.Entity

	switch {
	case strings.HasSuffix(sig, ".sig"), strings.HasSuffix(sig, ".gpg"):
		ent, err = openpgp.CheckDetachedSignature(kr, fFile, fSig)
	case strings.HasSuffix(sig, ".asc"):
		ent, err = openpgp.CheckArmoredDetachedSignature(kr, fFile, fSig)
	default:
		// Try to open as an armored file if we don't know the extension
		ent, err = openpgp.CheckArmoredDetachedSignature(kr, fFile, fSig)
	}

	errExit(err)

	for _, id := range ent.Identities {
		fmt.Printf("%q\n", id.Name)
	}
	fmt.Println("Signature OK.")
}
