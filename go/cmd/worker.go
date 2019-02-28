package cmd

import (
	"github.com/bloom42/phaser/worker"
	"github.com/bloom42/rz-go/v2"
	"github.com/bloom42/rz-go/v2/log"
	"github.com/spf13/cobra"
)

var workerDataFolder string
var workerAssetsFolder string

func init() {
	workerCmd.Flags().StringVarP(&workerAssetsFolder, "assets", "a", "assets", "The assets folder")
	workerCmd.Flags().StringVar(&workerDataFolder, "data", "scans", "The data directory where to store temporary scans data")

	rootCmd.AddCommand(workerCmd)
}

// run the scanner as a worker, waiting messages from remote sources
var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run the scanner as a worker. Wait for messages from remote sources. Configuration is done with environment variable",
	Run: func(cmd *cobra.Command, args []string) {
		var w worker.Worker

		if err := w.Run(); err != nil {
			log.Fatal("running worker", rz.Err(err))
		}
	},
}
