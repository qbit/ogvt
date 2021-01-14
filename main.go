package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
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

var flags struct {
	sig, file, pub string
}

func main() {
	_ = protect.Pledge("stdio unveil rpath")

	flag.StringVar(&flags.sig, "sig", "",
		"path to signature file; if file contains cleartext message\n"+
			"with signature, -file must be unset")
	flag.StringVar(&flags.file, "file", "",
		"path to unsigned message file; incompatible with cleartext\n"+
			"signatures")
	flag.StringVar(&flags.pub, "pub", "", "path to pubkey file")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	_ = protect.Unveil(flags.sig, "r")
	_ = protect.Unveil(flags.file, "r")
	_ = protect.Unveil(flags.pub, "r")
	ext := filepath.Ext(flags.sig)
	var signoext string
	if flags.file == "" && ext != "" {
		signoext = flags.sig[:len(flags.sig)-len(ext)]
		_ = protect.Unveil(signoext, "r")
	}
	_ = protect.UnveilBlock()

	pubFi, err := os.Open(flags.pub)
	errExit(err)
	defer pubFi.Close()
	kr, err := openpgp.ReadArmoredKeyRing(pubFi)
	if err != nil {
		fmt.Printf("Can't parse public key %q\n%s\n", flags.pub, err)
		os.Exit(1)
	}

	var sig, message io.Reader
	var clearsigBlock *clearsign.Block
	var armored bool
	clearsigned := func(data []byte) bool {
		clearsigBlock, _ = clearsign.Decode(data)
		return clearsigBlock != nil
	}

	sigBytes, err := ioutil.ReadFile(flags.sig)
	errExit(err)
	switch {
	case clearsigned(sigBytes):
		if flags.file != "" {
			fmt.Printf("-file is incompatible with cleartext signatures\n")
			os.Exit(1)
		}
		message = bytes.NewReader(clearsigBlock.Bytes)
		sig = clearsigBlock.ArmoredSignature.Body
		armored = false // Body provides decoded signature
	case flags.file == "":
		// Check for a message file with the .sig extensions removed
		flags.file = signoext
		fallthrough
	default:
		messageFi, err := os.Open(flags.file)
		if os.IsNotExist(err) {
			fmt.Printf("signature %s does not provide cleartext, and no "+
				"message %s found\n", flags.sig, flags.file)
			os.Exit(1)
		}
		errExit(err)
		defer messageFi.Close()

		message = messageFi
		sig = bytes.NewReader(sigBytes)
		// Unless signature file uses .gpg or .sig extensions, read
		// ascii armored input.  This covers .asc signatures, and
		// assumes armoring if the extension is otherwise unknown.
		armored = ext != ".gpg" && ext != ".sig"
	}

	var ent *openpgp.Entity
	if armored {
		ent, err = openpgp.CheckArmoredDetachedSignature(kr, message, sig)
	} else {
		ent, err = openpgp.CheckDetachedSignature(kr, message, sig)
	}
	errExit(err)

	for _, id := range ent.Identities {
		fmt.Printf("%q\n", id.Name)
	}
	fmt.Println("Signature OK.")
}
