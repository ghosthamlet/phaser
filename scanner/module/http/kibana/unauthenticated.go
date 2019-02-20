package kibana

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
	return "http/kibana/unauthenticated_access"
}

func (UnauthenticatedAccess) Description() string {
	return "Check for kibana Unauthenticated Access"
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
	// response, _ := httputil.DumpResponse(res, true)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	res.Body.Close()
	bodyStr := string(body)

	if strings.Contains(bodyStr, `</head><body kbn-chrome id="kibana-body"><kbn-initial-state`) ||
		strings.Contains(bodyStr, `<div class="ui-app-loading"><h1><strong>Kibana</strong><small>&nbsp;is loading.`) ||
		strings.Index(bodyStr, `<script>var hashRoute = '/app/kibana';`) == 0 ||
		strings.Contains(bodyStr, "<div class=\"kibanaWelcomeLogo\"></div></div></div><div class=\"kibanaWelcomeText\">Loading Kibana</div></div>") {
		ret := VulnerableURL{URL}
		return ret, errs
	}

	return ret, errs
}
