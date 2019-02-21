package git

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type HeadFileDisclosure struct{}

func (HeadFileDisclosure) Name() string {
	return "http/git/head_file_disclosure"
}

func (HeadFileDisclosure) Description() string {
	return "Check for .git/head file disclosure"
}

func (HeadFileDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (HeadFileDisclosure) Version() string {
	return "0.1.0"
}

type gitHeadData struct {
	URL      string `json:"url"`
	Response string `json:"response"`
}

func (HeadFileDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/.git/HEAD", protocol, target.Host, port.ID)
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
	bodyStr := string(body)

	if strings.Index(strings.ToLower(strings.TrimSpace(bodyStr)), "ref:") == 0 {
		ret = gitHeadData{
			URL:      URL,
			Response: bodyStr,
		}
	}

	return ret, errs
}
