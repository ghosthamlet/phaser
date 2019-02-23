package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type DirectoryListingInformationDisclosure struct{}

func (DirectoryListingInformationDisclosure) Name() string {
	return "http/directory_listing_information_disclosure"
}

func (DirectoryListingInformationDisclosure) Description() string {
	return "Check for enabled direstory listing, which often leak information"
}

func (DirectoryListingInformationDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (DirectoryListingInformationDisclosure) Version() string {
	return "0.1.0"
}

const DIRECTORY_LISTING_REGEXP = "<title>Index of .*<\\/title>"

func (DirectoryListingInformationDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/", protocol, target.Host, port.ID)
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

	matched, err := regexp.MatchString(DIRECTORY_LISTING_REGEXP, bodyStr)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	if matched {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
