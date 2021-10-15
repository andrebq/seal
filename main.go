package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "seal",
		Usage: "Encrypt/Decrypt things using nacl secret box",
		Commands: []*cli.Command{
			encryptCmd(),
			decryptCmd(),
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(os.Stderr, "\n")
}
