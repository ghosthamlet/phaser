package worker

import (
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/bloom42/common/async"
	"github.com/bloom42/common/phaser"
	"github.com/bloom42/rz-go"
	"github.com/bloom42/rz-go/log"
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
		log.Error("marshaling scan_started message", rz.Err(err), rz.String("report.id", reportID))
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
		log.Error("sending scan_started to SQS", rz.Err(err), rz.String("report.id", reportID))
		return err
	}

	log.Info("scan started message successfully sent", rz.String("report_id", reportID))
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
		log.Error("marshaling scan_completed message", rz.Err(err), rz.Interface("scan_id", scan.ID),
			rz.Interface("report_id", scan.ReportID))
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
		log.Error("sending scan result to SQS", rz.Err(err), rz.Interface("scan_id", scan.ID),
			rz.Interface("report_id", scan.ReportID))
		return err
	}

	log.Info("scan result successfully sent to API", rz.Interface("scan_id", scan.ID), rz.Interface("report_id", scan.ReportID))
	return nil
}
