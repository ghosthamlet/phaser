package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type EnvFileDisclosure struct{}

func (EnvFileDisclosure) Name() string {
	return "http/env_file_disclosure"
}

func (EnvFileDisclosure) Description() string {
	return "Check for .env file disclosure"
}

func (EnvFileDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (EnvFileDisclosure) Version() string {
	return "0.1.0"
}

func (EnvFileDisclosure) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"

	if !port.HTTP && !port.HTTPS {
		return ret, errs
	}
	if port.HTTPS {
		protocol = "https"
	}

	URL := fmt.Sprintf("%s://%s:%d/.env", protocol, target.Host, port.ID)
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
	count := 0

	clues := []string{
		"APP_ENV=",
		"DB_CONNECTION=",
		"DB_HOST=",
		"DB_PORT=",
		"DB_DATABASE=",
		"DB_USERNAME=",
		"DB_PASSWORD=",
		"REDIS_HOST=",
		"REDIS_PASSWORD=",
		"REDIS_PORT=",
		"AWS_KEY=",
		"AWS_SECRET=",
		"AWS_REGION=",
		"AWS_BUCKET=",
		"APP_NAME=",
		"AUTH_KEY=",
		"AUTH_SALT=",
		"LOGGED_IN_KEY=",
		"WP_ENV=",
		"S3_BUCKET=",
		"DATABASE_URL=",
		"REDIS_URL=",
		"EXPRESS_LOGGER=",
		"NEW_RELIC_LICENSE_KEY=",
	}

	for _, clue := range clues {
		if strings.Contains(bodyStr, clue) {
			count += 1
		}
	}

	if count >= 1 {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}
