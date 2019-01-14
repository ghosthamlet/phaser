package cmd

import (
	"path/filepath"
	"os"

	"github.com/bloom42/astro-go/log"
	"github.com/spf13/cobra"
	"gitlab.com/bloom42/phaser/scanner"
	"gitlab.com/bloom42/phaser/scanner/profile"
	"github.com/bloom42/sane-go"
	"github.com/bloom42/astro-go"
	"gitlab.com/bloom42/shared/phaser"
)

var scanTargetsFile string
var scanProfileFile string
var scanOutputFormat string
var scanEnableDebug bool
var scanOutputFolder string
var scanAssetsFolder string

func init() {
	scanCmd.Flags().StringVarP(&scanTargetsFile, "targets", "t", "", "A file containing new line separated targets (use -- for stdin, and fallback to arguments if not provided)")
	scanCmd.Flags().StringVarP(&scanProfileFile, "profile", "p", "", "A .sane file containing the scanner's profile. Default to 'network'")
	scanCmd.Flags().StringVarP(&scanOutputFormat, "format", "f", "text", "The logging ouput format. Valid values are [text, json]")
	scanCmd.Flags().BoolVarP(&scanEnableDebug, "debug", "d", false, "Set logging level to debug")
	scanCmd.Flags().StringVarP(&scanOutputFolder, "output", "o", "", "The output folder for the scan data. Default to 'scans/target'")
	scanCmd.Flags().StringVarP(&scanAssetsFolder, "assets", "a", "assets", "The assets folder")

	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run the scanner from CLI. Configuration is done with flags",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		// TODO: parse targets
		var scanProfile phaser.Profile

		log.Config(
			astro.SetFormatter(astro.NewCLIFormatter()),
			astro.SetLevel(astro.InfoLevel),
		)

		// configure output format
		if scanOutputFormat == "json" {
			log.Config(astro.SetFormatter(astro.JSONFormatter{}))
		} else if scanOutputFormat != "text" {
			log.Fatalf("%s is not a valid output format", scanOutputFormat)
		}

		// configure log level
		if scanEnableDebug == false {
			log.Config(astro.SetLevel(astro.InfoLevel))
		}

		// load scan profile
		if scanProfileFile != "" {
			log.With("file", scanProfileFile).Info("loading profile file")
			err = sane.Load(scanProfileFile, &scanProfile)
			if err != nil {
				log.Fatal(err.Error())
			}
		} else {
			log.With("profile", "network").Info("using default profile")
			scanProfile = profile.Network
		}

		if scanOutputFolder == "" {
			scanOutputFolder = filepath.Join("scans", args[0])
		}
		os.MkdirAll(scanOutputFolder, os.ModePerm)

		scanConfig := phaser.Config{
			Profile: scanProfile,
			Targets: args,
			Folder: &scanOutputFolder,
			Assets: scanAssetsFolder,
		}

		scanner.Run(scanConfig)
	},
}
