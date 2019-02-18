package worker

import (
	"encoding/json"
	"strings"
	"os"

	"github.com/bloom42/rz-go/v2/log"
	"github.com/bloom42/rz-go/v2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bloom42/phaser/scanner"
	"github.com/bloom42/phaser/scanner/profile"
	commonasync "github.com/bloom42/common/async"
	"github.com/bloom42/phaser/phaser"
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
	log.Info("listenning queue for async messages", rz.String("queue", qURL))
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
			log.Error("receiving SQS message", rz.Err(err))
			continue
		}

		log.Info("sqs request ended", rz.Int("messages", len(result.Messages)))

		if len(result.Messages) == 0 {
			continue
		}

		for _, message := range result.Messages {

			asyncMessage := commonasync.DecodedMessage{}
			err := json.Unmarshal([]byte(*message.Body), &asyncMessage)
			if err != nil {
				log.Error("decoding async message", rz.Err(err))
				continue
			}

			switch asyncMessage.Type {
			case "scan_queued":
				scanMessage := phaser.ScanQueuedMessage{}
				err := json.Unmarshal(asyncMessage.Data, &scanMessage)
				if err != nil {
					log.Error("decoding scan_queued message data", rz.Err(err))
					continue
				}
				log.Info("scan_queued message successfully received and decoded", rz.String("scan.id", scanMessage.ScanID))
				go worker.runScan(scanMessage)
			}

			_, err = sqsService.DeleteMessage(&sqs.DeleteMessageInput{
				QueueUrl:      &qURL,
				ReceiptHandle: message.ReceiptHandle,
			})

			if err != nil {
				log.Error("deleting message from SQS queue", rz.Err(err))
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
