package worker

import (
	"fmt"
	"os"

	"github.com/bloom42/denv-go"
	"github.com/bloom42/dotenv-go"
	"github.com/bloom42/phaser/version"
	"github.com/bloom42/rz-go/v2"
	"github.com/bloom42/rz-go/v2/log"
	"github.com/getsentry/raven-go"
)

type config struct {
	GoEnv              string
	AWSSecretAccessKey string
	AWSAccessKeyID     string
	AWSRegion          string
	AWSSQSAPIToPhaser  string
	AWSSQSPhaserToAPI  string
	AWSS3Bucket        string
	AssetsPath         string
	SentryURL          string
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

var DefaultEnvVars = denv.Env{
	"GO_ENV":      "development",
	"ASSETS_PATH": "assets",
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
	dotenv.Load()
	checkEnv()
	denv.Init(DefaultEnvVars)
	var conf config

	errorCallerHook := rz.HookFunc(func(e *rz.Event, level rz.LogLevel, msg string) {
		if level >= rz.ErrorLevel {
			e.Append(rz.Caller(true))
		}
	})

	log.SetLogger(log.With(rz.Hooks(errorCallerHook)))

	conf.GoEnv = os.Getenv("GO_ENV")
	raven.SetEnvironment(conf.GoEnv)
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
		log.SetLogger(log.With(rz.Level(rz.InfoLevel)))
	} else {
		log.SetLogger(log.With(rz.Formatter(rz.FormatterConsole())))
	}

	hostname, _ := os.Hostname()
	log.Append(
		rz.Dict("service", log.NewDict(rz.String("name", version.Name), rz.String("version", version.Version))),
		rz.String("host", hostname),
		rz.String("environment", conf.GoEnv),
	)

	log.Info("worker configuration successfully loaded",
		rz.String("aws_region", conf.AWSRegion),
		rz.String("aws_sqs_api_to_phaser", conf.AWSSQSAPIToPhaser),
		rz.String("aws_sqs_phaser_to_api", conf.AWSSQSPhaserToAPI),
		rz.String("aws_s3_bucket", conf.AWSS3Bucket),
		rz.String("assets_path", conf.AssetsPath),
	)

	worker.config = conf
	return nil
}
