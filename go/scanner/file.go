package scanner

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/rz-go/v2"
)

type hashs struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

func hash(logger *rz.Logger, filePath string, reader *bytes.Reader) (hashs, error) {
	var ret hashs

	// md5
	h := md5.New()
	if _, err := io.Copy(h, reader); err != nil {
		logger.Error("hashing md5", rz.Err(err), rz.String("file", filePath))
		return ret, err
	}
	reader.Seek(0, 0)
	ret.MD5 = hex.EncodeToString(h.Sum(nil))

	//sha1
	h = sha1.New()
	if _, err := io.Copy(h, reader); err != nil {
		logger.Error("hashing sha1", rz.Err(err), rz.String("file", filePath))
		return ret, err
	}
	reader.Seek(0, 0)
	ret.SHA1 = hex.EncodeToString(h.Sum(nil))

	// sha256
	h = sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		logger.Error("hashing sha256", rz.Err(err), rz.String("file", filePath))
		return ret, err
	}
	reader.Seek(0, 0)
	ret.SHA256 = hex.EncodeToString(h.Sum(nil))

	// sha512
	h = sha512.New()
	if _, err := io.Copy(h, reader); err != nil {
		logger.Error("hashing sha512", rz.Err(err), rz.String("file", filePath))
		return ret, err
	}
	reader.Seek(0, 0)
	ret.SHA512 = hex.EncodeToString(h.Sum(nil))

	return ret, nil
}

// save a file in the output folder
func saveFile(scan *phaser.Scan, filePath string, data []byte) (phaser.File, error) {
	var err error
	reader := bytes.NewReader(data)
	var ret phaser.File
	logger := rz.FromCtx(scan.Ctx)

	hashs, err := hash(logger, filePath, reader)
	if err != nil {
		logger.Error("computing hashs", rz.Err(err), rz.String("file", filePath))
		return ret, err
	}
	ret = phaser.File{
		Path:   filePath,
		MD5:    hashs.MD5,
		SHA1:   hashs.SHA1,
		SHA256: hashs.SHA256,
		SHA512: hashs.SHA512,
	}

	// if scan.Config.AwsSession != nil { // save to a cloud bucket
	// 	filePath = filepath.Join("platform", "phaser", "scans", *scan.ID, "reports", *scan.ReportID, filePath)
	// 	s3Service := s3.New(scan.Config.AwsSession)
	// 	logger.With("file", filePath).Debug("writing file to s3")
	// 	_, err = s3Service.PutObject(&s3.PutObjectInput{
	// 		Bucket: aws.String(*scan.Config.AWSS3Bucket),
	// 		Key:    aws.String(filePath),
	// 		Body:   reader,
	// 	})
	// } else
	// save to local FS
	filePath = filepath.Join(scan.Config.ModuleResultFolder, filePath)
	logger.Info("writing file to fs", rz.String("file", filePath))
	err = ioutil.WriteFile(filePath, data, 0600)

	return ret, err
}
