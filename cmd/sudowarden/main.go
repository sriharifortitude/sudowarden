// Command sudowarden finds the sudoers rules that give more than they seem to.
package main

import (
	"os"

	"github.com/sriharifortitude/sudowarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
