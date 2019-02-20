package gitlab

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type OpenRegistration struct{}

func (OpenRegistration) Name() string {
	return "gitlab/open_registration"
}

func (OpenRegistration) Description() string {
	return "Check if the gitlab instance is open to registration"
}

func (OpenRegistration) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (OpenRegistration) Version() string {
	return "0.1.0"
}

type VulnerableURL struct {
	URL string `json:"url"`
}

func (OpenRegistration) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	var ret interface{}
	errs := []error{}
	protocol := "http"
	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d", protocol, target.Host, port.ID)
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

	if strings.Contains(bodyStrLower, "gitlab") && strings.Contains(string(body), "Register") {
		ret = VulnerableURL{
			URL: URL,
		}
	}

	return ret, errs
}
