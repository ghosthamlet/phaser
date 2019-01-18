package worker

import (
	"fmt"
	"os"

	"github.com/astrolib/godotenv"
	"github.com/bloom42/astro-go"
	"github.com/bloom42/astro-go/log"
	"github.com/bloom42/phaser/version"
	"github.com/bloom42/denv-go"
)

type config struct {
	GoEnv                      string
	AWSSecretAccessKey         string
	AWSAccessKeyID             string
	AWSRegion                  string
	AWSSQSAPIToPhaser string
	AWSSQSPhaserToAPI string
	AWSS3Bucket                string
	AssetsPath                 string
	SentryURL string
}

// RequiredEnvVars are the required environment variables to run the server
var RequiredEnvVars = []string{
	"AWS_SECRET_ACCESS_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_REGION",
	"AWS_SQS_PHASER_TO_API",
	"AWS_SQS_API_TO_PHASER",
	"AWS_S3_BUCKET",
	"SENTRY_URL",
}

// CheckEnv checks if the required environment variables are present
func checkEnv() {
	for _, v := range RequiredEnvVars {
		if os.Getenv(v) == "" {
			panic(fmt.Sprintf("Missing environment variable: %s", v))
		}
	}
}

// Init loads the server configuration
func (worker *Worker) initConfig() error {
	godotenv.Load()
	checkEnv()
	denv.Init(denv.Env{
		"GO_ENV":      "development",
		"ASSETS_PATH": "assets",
	})
	var conf config

	conf.GoEnv = os.Getenv("GO_ENV")
	conf.AssetsPath = os.Getenv("ASSETS_PATH")

	conf.AWSRegion = os.Getenv("AWS_REGION")
	conf.AWSAccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
	conf.AWSSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	conf.AWSSQSAPIToPhaser = os.Getenv("AWS_SQS_API_TO_PHASER")
	conf.AWSSQSPhaserToAPI = os.Getenv("AWS_SQS_PHASER_TO_API")
	conf.AWSS3Bucket = os.Getenv("AWS_S3_BUCKET")
	conf.SentryURL = os.Getenv("SENTRY_URL")

	// configure logger
	if conf.GoEnv == "production" {
		log.Config(
			astro.SetFormatter(astro.JSONFormatter{}),
			astro.SetLevel(astro.InfoLevel),
		)
	} else {
		log.Config(astro.SetFormatter(astro.NewConsoleFormatter()))
	}

	hostname, _ := os.Hostname()
	log.Config(
		astro.AddFields(
			"service", map[string]string{"name": version.Name, "version": version.Version},
			"host", hostname,
			"environment", conf.GoEnv,
		),
	)

	log.With(
		"aws_region", conf.AWSRegion,
		"aws_sqs_api_to_phaser", conf.AWSSQSAPIToPhaser,
		"aws_sqs_phaser_to_api", conf.AWSSQSPhaserToAPI,
		"aws_s3_bucket", conf.AWSS3Bucket,
		"assets_path", conf.AssetsPath,
	).Debug("worker configuration successfully loaded")

	worker.config = conf
	return nil
}
