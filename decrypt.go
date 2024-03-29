package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

func decryptCmd() *cli.Command {
	var file string
	var readFromStdin bool
	return &cli.Command{
		Name:    "decrypt",
		Aliases: []string{"d"},
		Usage:   "Encrypt the given file",
		Action: func(c *cli.Context) error {
			if !strings.HasSuffix(file, fileSuffix) {
				return errors.New("Input file has to have .sealed as suffix")
			}
			data, err := ioutil.ReadFile(file)
			if err != nil {
				return err
			}
			if data[0] != version {
				return errors.New("file encrypted using a different version than expected [" + strconv.Itoa(int(data[0])) + "]")
			}
			data = data[1:]
			var salt salt
			copy(salt[:], data)
			data = data[8:]

			var nonce nonce
			copy(nonce[:], data)
			data = data[24:]
			var passwd []byte
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprint(os.Stdout, "Type the file password: \n")
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

			plain, ok := secretbox.Open(nil, data, (*[24]byte)(&nonce), (*[32]byte)(&key))
			if !ok {
				return errors.New("Unable to decrypt file. Please check password")
			}
			err = ioutil.WriteFile(file[:len(file)-len(fileSuffix)], plain, 0644)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "File %v unsealed to %v\n", file, file[:len(file)-len(fileSuffix)])
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
