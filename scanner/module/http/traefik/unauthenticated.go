package traefik

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type UnauthenticatedAccess struct{}

func (UnauthenticatedAccess) Name() string {
	return "http/traefik/unauthenticated_access"
}

func (UnauthenticatedAccess) Description() string {
	return "Check for traefik Unauthenticated Access"
}

func (UnauthenticatedAccess) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (UnauthenticatedAccess) Version() string {
	return "0.1.0"
}

type VulnerableURL struct {
	URL string `json:"url"`
}

func (UnauthenticatedAccess) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
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
	bodyStr := string(body)

	if (strings.Contains(bodyStr, "ng-app=\"traefik\"") &&
		strings.Contains(bodyStr, "href=\"https://docs.traefik.io\"") &&
		strings.Contains(bodyStr, "href=\"https://traefik.io\"")) ||
		strings.Contains(bodyStr, `fixed-top"><head><meta charset="utf-8"><title>Traefik</title><base`) {
		ret = VulnerableURL{URL}
	}

	return ret, errs
}
