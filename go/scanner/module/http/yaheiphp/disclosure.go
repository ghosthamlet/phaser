package yaheiphp

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type InformationDisclosure struct{}

func (InformationDisclosure) Name() string {
	return "http/yaheiphp/information_disclosure"
}

func (InformationDisclosure) Description() string {
	return "Check for Yahei (http://www.yahei.net) information disclosure"
}

func (InformationDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (InformationDisclosure) Version() string {
	return "0.1.0"
}

func (InformationDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	// TODO: also check tz_e.php
	URL := fmt.Sprintf("%s://%s:%d/proberv.php", protocol, target.Host, port.ID)
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

	if strings.Contains(bodyStr, "<title>Yahei-PHP") {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
