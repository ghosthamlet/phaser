package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"context"

	"github.com/bloom42/rz-go/v2"
	"github.com/bloom42/rz-go/v2/log"
	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner"
	"github.com/bloom42/uuid-go"
	"github.com/spf13/cobra"
)

var scanTargetsFile string
var scanProfileFile string
var scanOutputFormat string
var scanEnableDebug bool
var scanOutputFolder string
var scanAssetsFolder string
var scanConcurrency uint

func init() {
	scanCmd.Flags().StringVarP(&scanTargetsFile, "targets", "t", "", "A file containing new line separated targets (use -- for stdin, and fallback to arguments if not provided)")
	scanCmd.Flags().StringVarP(&scanProfileFile, "profile", "p", "network", "A .sane file containing the scanner's profile. Default to 'network'")
	scanCmd.Flags().StringVarP(&scanOutputFormat, "format", "f", "text", "The logging output format. Valid values are [text, json]")
	scanCmd.Flags().BoolVarP(&scanEnableDebug, "debug", "d", false, "Set logging level to debug")
	scanCmd.Flags().StringVarP(&scanOutputFolder, "output", "o", "scans", "The output folder for the scan data. Default to 'scans/target'")
	scanCmd.Flags().StringVarP(&scanAssetsFolder, "assets", "a", "assets", "The assets folder")
	scanCmd.Flags().UintVarP(&scanConcurrency, "concurrency", "c", 8, "Max targets to scan in parallel")

	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan [targets...]",
	Short: "Run the scanner from CLI. Configuration is done with flags",
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		var targetsStr []string

		log.SetLogger(log.With(rz.Level(rz.InfoLevel)))

		// configure output format
		if scanOutputFormat == "text" {
			log.SetLogger(log.With(rz.Formatter(rz.FormatterConsole())))
		} else if scanOutputFormat != "json" {
			log.Fatal(fmt.Sprintf("%s is not a valid output format", scanOutputFormat))
		}

		// configure log level
		if scanEnableDebug == false {
			log.SetLogger(log.With(rz.Level(rz.InfoLevel)))
		}

		// load targets
		if len(args) != 0 && scanTargetsFile != "" {
			log.Fatal("you can't have targets both from arguments and from file")
		}
		if len(args) == 0 && scanTargetsFile == "" {
			log.Error("please provide at least 1 target")
			cmd.Help()
		}

		if len(args) != 0 {
			targetsStr = args
		} else if scanTargetsFile != "" {
			targetsStr, err = readLines(scanTargetsFile)
			if err != nil {
				log.Fatal("reading target file", rz.Err(err), rz.String("path", scanTargetsFile))
			}
		}


		// load profile
		scanProfile, err := scanner.GetProfile(scanAssetsFolder, scanProfileFile)
		if err != nil {
			log.Fatal("loading profile", rz.Err(err))
		}

		uuidv4, err := uuid.NewV4()
		if err != nil {
			log.Fatal("failed to generate UUID", rz.Err(err))
		}

		scanOutputFolder = filepath.Join(scanOutputFolder, uuidv4.String())
		os.MkdirAll(scanOutputFolder, os.ModePerm)

		logger := log.With(rz.Fields(rz.String("scan.id", uuidv4.String())))
		ctx := logger.ToCtx(context.Background())

		scanConfig := phaser.Config{
			Profile:    scanProfile,
			Targets:    targetsStr,
			DataFolder: scanOutputFolder,
			AssetsFolder: scanAssetsFolder,
		}

		scanner.Run(ctx, scanConfig)
	},
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
