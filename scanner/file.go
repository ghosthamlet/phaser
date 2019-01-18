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

	"github.com/bloom42/astro-go/log"
	"github.com/bloom42/common/phaser"
)

type hashs struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

func hash(filePath string, reader *bytes.Reader) (hashs, error) {
	var ret hashs

	// md5
	h := md5.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.With("file", filePath, "err", err.Error()).Error("hashing md5")
		return ret, err
	}
	reader.Seek(0, 0)
	ret.MD5 = hex.EncodeToString(h.Sum(nil))

	//sha1
	h = sha1.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.With("file", filePath, "err", err.Error()).Error("hashing sha1")
		return ret, err
	}
	reader.Seek(0, 0)
	ret.SHA1 = hex.EncodeToString(h.Sum(nil))

	// sha256
	h = sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.With("file", filePath, "err", err.Error()).Error("hashing sha256")
		return ret, err
	}
	reader.Seek(0, 0)
	ret.SHA256 = hex.EncodeToString(h.Sum(nil))

	// sha512
	h = sha512.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.With("file", filePath, "err", err.Error()).Error("hashing sha512")
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

	hashs, err := hash(filePath, reader)
	if err != nil {
		log.With("file", filePath, "err", err.Error()).Error("computing hashs")
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
	// 	log.With("file", filePath).Debug("writing file to s3")
	// 	_, err = s3Service.PutObject(&s3.PutObjectInput{
	// 		Bucket: aws.String(*scan.Config.AWSS3Bucket),
	// 		Key:    aws.String(filePath),
	// 		Body:   reader,
	// 	})
	// } else
	if scan.Config.Folder != nil { // save to local FS
		filePath = filepath.Join(*scan.Config.Folder, filePath)
		log.With("file", filePath).Debug("writing file to fs")
		err = ioutil.WriteFile(filePath, data, 0600)
	} else {
		log.With("file", filePath).Error("aws_session nor folder are configured")
	}

	return ret, err
}
