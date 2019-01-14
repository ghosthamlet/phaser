package cmd

import (
	"github.com/bloom42/astro-go/log"
	"github.com/spf13/cobra"
	"gitlab.com/bloom42/phaser/worker"
)

func init() {
	rootCmd.AddCommand(workerCmd)
}

// run the scanner as a worker, waiting messages from remote sources
var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run the scanner as a worker. Wait for messages from remote sources. Configuration is done with environment variable",
	Run: func(cmd *cobra.Command, args []string) {
		var w worker.Worker

		if err := w.Run(); err != nil {
			log.Fatal(err.Error())
		}
	},
}
