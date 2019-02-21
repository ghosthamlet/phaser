package git

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type ConfigFileDisclosure struct{}

func (ConfigFileDisclosure) Name() string {
	return "http/git/config_file_disclosure"
}

func (ConfigFileDisclosure) Description() string {
	return "Check for .git/config file disclosure"
}

func (ConfigFileDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (ConfigFileDisclosure) Version() string {
	return "0.1.0"
}

type gitConfigData struct {
	URL      string `json:"url"`
	Response string `json:"response"`
}

func (ConfigFileDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/.git/config", protocol, target.Host, port.ID)
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

	matched, err := regexp.MatchString("\\[branch \"[^\"]*\"\\]", strings.ToLower(strings.TrimSpace(bodyStr)))
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	if matched {
		ret = gitConfigData{
			URL:      URL,
			Response: bodyStr,
		}
	}

	return ret, errs
}
