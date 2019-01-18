package worker

import (
	"encoding/json"
	"strings"
	"os"

	"github.com/bloom42/astro-go/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bloom42/phaser/scanner"
	"github.com/bloom42/phaser/scanner/profile"
	commonasync "github.com/bloom42/common/async"
	"github.com/bloom42/common/phaser"
	"github.com/getsentry/raven-go"
)

type Worker struct {
	awsSession *session.Session
	config     config
}

func (worker *Worker) init() error {
	raven.SetDSN(os.Getenv("SENTRY_URL"))

	err := worker.initConfig()
	if err != nil {
		return err
	}

	raven.SetEnvironment(worker.config.GoEnv)

	awsConf := aws.Config{
		Credentials: credentials.NewStaticCredentials(worker.config.AWSAccessKeyID, worker.config.AWSSecretAccessKey, ""),
	}
	awsConf.Region = aws.String(worker.config.AWSRegion)
	worker.awsSession = session.New(&awsConf)
	return nil
}

func (worker *Worker) Run() error {
	var err error

	err = worker.init()
	if err != nil {
		return err
	}

	sqsService := sqs.New(worker.awsSession)

	qURL := worker.config.AWSSQSAPIToPhaser
	log.With("queue", qURL).Info("listenning queue for async messages")
	for {
		result, err := sqsService.ReceiveMessage(&sqs.ReceiveMessageInput{
			AttributeNames: []*string{
				aws.String(sqs.MessageSystemAttributeNameSentTimestamp),
			},
			MessageAttributeNames: []*string{
				aws.String(sqs.QueueAttributeNameAll),
			},
			QueueUrl:            &qURL,
			MaxNumberOfMessages: aws.Int64(1),
		})

		if err != nil {
			log.With("err", err.Error()).Error("error receiving SQS message")
			continue
		}

		log.With("messages", len(result.Messages)).Debug("sqs request ended")

		if len(result.Messages) == 0 {
			continue
		}

		for _, message := range result.Messages {

			asyncMessage := commonasync.DecodedMessage{}
			err := json.Unmarshal([]byte(*message.Body), &asyncMessage)
			if err != nil {
				log.With("err", err.Error()).Error("error decoding async message")
				continue
			}

			switch asyncMessage.Type {
			case "scan_queued":
				scanMessage := phaser.ScanQueuedMessage{}
				err := json.Unmarshal(asyncMessage.Data, &scanMessage)
				if err != nil {
					log.With("err", err.Error()).Error("error decoding scan_queued message data")
					continue
				}
				log.With("message", scanMessage).Info("scan_queued message successfully received and decoded")
				go worker.runScan(scanMessage)
			}

			_, err = sqsService.DeleteMessage(&sqs.DeleteMessageInput{
				QueueUrl:      &qURL,
				ReceiptHandle: message.ReceiptHandle,
			})

			if err != nil {
				log.With("err", err.Error()).Error("error deleting message from SQS queue")
				continue
			}
		}

	}
}

func (worker *Worker) runScan(message phaser.ScanQueuedMessage) {
	prof := profile.Network
	if strings.ToLower(message.Profile) == profile.ApplicationName {
		prof = profile.Application
	}

	// TODO: qeueue
	scanConfig := phaser.Config{
		Profile: prof,
		Targets: message.Targets,
		ID: &message.ScanID,
		ReportID: &message.ReportID,
		AWSS3Bucket: &worker.config.AWSS3Bucket,
		Assets: worker.config.AssetsPath,
	}
	scan := scanner.NewScan(scanConfig)
	worker.sendScanStarted(*scan.ReportID, scan.StartedAt)
	scanner.RunScan(scan)
	worker.sendScanCompleted(*scan)
}
