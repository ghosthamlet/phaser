package worker

import (
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bloom42/astro-go/log"
	"github.com/bloom42/common/async"
	"github.com/bloom42/common/phaser"
)

func (worker *Worker) sendScanStarted(reportID string, startedAt time.Time) error {
	svc := sqs.New(worker.awsSession)

	data := phaser.ScanStartedMessage{
		ReportID:  reportID,
		StartedAt: startedAt,
	}
	message := async.Message{
		Type: "scan_started",
		Data: data,
	}

	encodedMessage, err := json.Marshal(message)
	if err != nil {
		log.With("err", err.Error, "report_id", reportID).
			Error("marshaling scan_started message")
		return err
	}

	// URL to our queue
	qURL := worker.config.AWSSQSPhaserToAPI
	_, err = svc.SendMessage(&sqs.SendMessageInput{
		DelaySeconds: aws.Int64(0),
		MessageBody:  aws.String(string(encodedMessage)),
		QueueUrl:     &qURL,
	})

	if err != nil {
		log.With("err", err.Error, "report_id", reportID).
			Error("sending scan_started to SQS")
		return err
	}

	log.With("report_id", reportID).Info("scan started message successfully sent")
	return nil
}

func (worker *Worker) sendScanCompleted(scan phaser.Scan) error {
	svc := sqs.New(worker.awsSession)
	messageData := phaser.ScanCompletedMessage{
		ReportID: *scan.ReportID,
		File:     scan.ResultFile,
	}

	message := async.Message{
		Type: "scan_completed",
		Data: messageData,
	}

	encodedMessage, err := json.Marshal(message)
	if err != nil {
		log.With("err", err.Error, "scan_id", scan.ID, "report_id", scan.ReportID).
			Error("marshaling scan_completed message")
		return err
	}

	// URL to our queue
	qURL := worker.config.AWSSQSPhaserToAPI
	_, err = svc.SendMessage(&sqs.SendMessageInput{
		DelaySeconds: aws.Int64(0),
		MessageBody:  aws.String(string(encodedMessage)),
		QueueUrl:     &qURL,
	})

	if err != nil {
		log.With("err", err.Error, "scan_id", scan.ID, "report_id", scan.ReportID).
			Error("sending scan result to SQS")
		return err
	}

	log.With("scan_id", scan.ID, "report_id", scan.ReportID).Info("scan result successfully sent to API")
	return nil
}
