package etcd

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
	return "http/etcd/unauthenticated_access"
}

func (UnauthenticatedAccess) Description() string {
	return "Check for ETCD Unauthenticated Access"
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

// type EtcdVersion struct {
// 	EtcdServer  string `json:"etcdserver"`
// 	EtcdCluster string `json:"etcdcluster"`
// }

func (UnauthenticatedAccess) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"
	// var info EtcdVersion

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/version", protocol, target.Host, port.ID)
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

	if strings.Contains(bodyStr, "\"etcdserver\"") &&
		strings.Contains(bodyStr, "\"etcdcluster\"") &&
		len(bodyStr) < 130 {
		ret = VulnerableURL{URL}
	}

	return ret, errs
}
