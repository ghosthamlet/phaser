package http

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type DSStoreFileDisclosure struct{}

func (DSStoreFileDisclosure) Name() string {
	return "http/dsstore_file_disclosure"
}

func (DSStoreFileDisclosure) Description() string {
	return "Check for .DS_Store file disclosure"
}

func (DSStoreFileDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (DSStoreFileDisclosure) Version() string {
	return "0.1.0"
}

func (DSStoreFileDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/.DS_Store", protocol, target.Host, port.ID)
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	req.Header.Set("User-Agent", scan.Profile.HTTP.UserAgent)
	res, err := scan.HTTPClient.Do(req)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	// response, _ := httputil.DumpResponse(res, true)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	res.Body.Close()

	if bytes.Equal(body[0:8], []byte{0x0, 0x0, 0x0, 0x1, 0x42, 0x75, 0x64, 0x31}) {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
