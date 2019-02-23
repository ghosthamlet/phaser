package prometheus

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type DashboardUnauthenticatedAccess struct{}

func (DashboardUnauthenticatedAccess) Name() string {
	return "http/prometheus/dashboard_unauthenticated_access"
}

func (DashboardUnauthenticatedAccess) Description() string {
	return "Check for prometheus Unauthenticated Access"
}

func (DashboardUnauthenticatedAccess) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (DashboardUnauthenticatedAccess) Version() string {
	return "0.1.0"
}

func (DashboardUnauthenticatedAccess) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
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
	// response, _ := httputil.DumpResponse(res, true)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	res.Body.Close()
	bodyStr := string(body)

	if strings.Contains(bodyStr, "<title>Prometheus Time Series Collection and Processing Server</title>") {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
