package main

import (
	stdlog "log"
	"os"

	"gitlab.com/bloom42/phaser/cmd"
)

func main() {
	stdlog.SetOutput(os.Stderr)
	cmd.Execute()
	// if err := cmd.Execute(); err != nil {
	// 	// log.Fatal(err.Error())
	// }
}
