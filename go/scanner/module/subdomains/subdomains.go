package subdomains

import (
	"strings"

	"github.com/astrolib/govalidator"
	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type Subdomains struct{}

func (Subdomains) Name() string {
	return "subdomains"
}

func (Subdomains) Description() string {
	return "Find subdomains for a given domain"
}

func (Subdomains) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (Subdomains) Version() string {
	return "0.1.0"
}

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

type crtshDomain struct {
	Domain string `db:"domain"`
}

func (ports Subdomains) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	uniqDomains := map[string]bool{}
	errs := []error{}
	var ret module.Result
	domains := []string{}

	crtshdb, err := sqlx.Connect("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable")
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	subdomainsPattern := "%." + target.Host
	crtshDomains := []crtshDomain{}
	idx := strings.Index(subdomainsPattern, "%")
	idxrev := strings.Index(reverseStr(subdomainsPattern), "%")
	if idx != -1 && idx < idxrev {
		err = crtshdb.Select(&crtshDomains, `SELECT DISTINCT ci.NAME_VALUE as domain
			FROM certificate_identity ci
			WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))`, subdomainsPattern)
	} else {
		err = crtshdb.Select(&crtshDomains, `SELECT DISTINCT ci.NAME_VALUE as domain
			FROM certificate_identity ci
			WHERE lower(ci.NAME_VALUE) LIKE lower($1)`, subdomainsPattern)
	}
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	for _, crtshDomain := range crtshDomains {
		domain := strings.ToLower(strings.TrimSpace(crtshDomain.Domain))
		if govalidator.IsDNSName(domain) {
			uniqDomains[domain] = true
		}
	}

	for domain := range uniqDomains {
		domains = append(domains, domain)
	}
	ret = domains

	return ret, errs
}
