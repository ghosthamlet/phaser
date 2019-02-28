package git

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type DirectoryDisclosure struct{}

func (DirectoryDisclosure) Name() string {
	return "http/git/directory_disclosure"
}

func (DirectoryDisclosure) Description() string {
	return "Check for .git directory disclosure"
}

func (DirectoryDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (DirectoryDisclosure) Version() string {
	return "0.1.0"
}

func (DirectoryDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/.git", protocol, target.Host, port.ID)
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

	if strings.Contains(bodyStr, "HEAD") == true &&
		strings.Contains(bodyStr, "refs") == true &&
		strings.Contains(bodyStr, "config") == true &&
		strings.Contains(bodyStr, "index") == true &&
		strings.Contains(bodyStr, "objects") == true {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
