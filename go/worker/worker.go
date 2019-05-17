package worker

import (
	"encoding/json"
	"context"

	"github.com/bloom42/rz-go/v2/log"
	"github.com/bloom42/rz-go/v2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bloom42/phaser/scanner"
	"github.com/bloom42/phaser/worker/config"
	"github.com/bloom42/phaser/common/async"
	"github.com/bloom42/phaser/common/phaser"
)

type Worker struct {
	awsSession *session.Session
}

func (worker *Worker) init() error {
	err := config.Init()
	if err != nil {
		return err
	}

	awsConf := aws.Config{
		Credentials: credentials.NewStaticCredentials(config.AWSAccessKeyID, config.AWSSecretAccessKey, ""),
	}
	awsConf.Region = aws.String(config.AWSRegion)
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

	qURL := config.AWSSQSAPIToPhaser
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

			asyncMessage := async.DecodedMessage{}
			err := json.Unmarshal([]byte(*message.Body), &asyncMessage)
			if err != nil {
				log.Error("decoding async message", rz.Err(err))
				continue
			}

			switch asyncMessage.Type {
			case "scan_queued":
				scanMessage := phaser.ScanQueuedMessage{}
				err := json.Unmarshal(asyncMessage.ModuleResult, &scanMessage)
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
	//  message.Profile must be either "network" or "application", nothing else
	scanProfile, _ := scanner.GetProfile(config.AssetsFolder, message.Profile)

	// TODO: qeueue
	scanConfig := phaser.Config{
		Profile: scanProfile,
		Targets: message.Targets,
		ID: &message.ScanID,
		ReportID: &message.ReportID,
		AWSS3Bucket: &config.AWSS3Bucket,
		AssetsFolder: config.AssetsFolder,
	}
	ctx := context.Background()
	scan := scanner.NewScan(ctx, scanConfig)
	worker.sendScanStarted(*scan.ReportID, scan.StartedAt)
	scanner.RunScan(scan)
	worker.sendScanCompleted(*scan)
}
