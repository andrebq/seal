package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

type (
	nonce     [24]byte
	secretKey [32]byte
	salt      [8]byte
)

const (
	fileSuffix = ".sealed"
	version    = 0x01
)

func encryptCmd() *cli.Command {
	var file string
	var readFromStdin bool
	return &cli.Command{
		Name:    "encrypt",
		Aliases: []string{"e"},
		Usage:   "Encrypt the given file",
		Action: func(c *cli.Context) error {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				return err
			}
			var nonce nonce
			_, err = rand.Read(nonce[:])
			if err != nil {
				return err
			}
			var salt salt
			_, err = rand.Read(salt[:])
			if err != nil {
				return err
			}
			var passwd []byte
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprint(os.Stdout, "Type the file password: ")
				passwd, err = terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
			} else if !readFromStdin {
				return errors.New("Stdin is not a terminal but the flags do not allow from passphrases from stdin")
			} else {
				passwd, err = ioutil.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				passwd = bytes.TrimSpace(passwd)
			}
			var key secretKey
			copy(key[:], argon2.IDKey(passwd, salt[:], 10, 64*1024, 4, 32))

			out := &bytes.Buffer{}

			// header
			out.Write([]byte{version})
			out.Write(salt[:])
			out.Write(nonce[:])

			out.Write(secretbox.Seal(nil, data, (*[24]byte)(&nonce), (*[32]byte)(&key)))
			err = ioutil.WriteFile(file+fileSuffix, out.Bytes(), 0644)
			if err != nil {
				return err
			}
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "inputFile",
				Aliases:     []string{"i"},
				Usage:       "Name of the file to encrypt",
				Destination: &file,
			},
			&cli.BoolFlag{
				Name:        "passphrase-from-stdin",
				Aliases:     []string{"stdin-pass", "s"},
				Usage:       "Read the passphrase from standard input",
				Destination: &readFromStdin,
				Value:       readFromStdin,
			},
		},
	}
}
