package mysql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
	_ "github.com/go-sql-driver/mysql"
)

type UnauthenticatedAccess struct{}

func (UnauthenticatedAccess) Name() string {
	return "mysql/unauthenticated_access"
}

func (UnauthenticatedAccess) Description() string {
	return "Check for mysql Unauthenticated Access"
}

func (UnauthenticatedAccess) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (UnauthenticatedAccess) Version() string {
	return "0.1.0"
}

func (UnauthenticatedAccess) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result

	if port.HTTP || port.HTTPS {
		return ret, errs
	}

	URL := fmt.Sprintf("root@tcp(%s:%d)/?timeout=8s", target.Host, port.ID)
	db, err := sql.Open("mysql", URL)
	if err != nil {
		return ret, errs
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Second * 8)
	err = db.Ping()
	if err != nil {
		return ret, errs
	}

	// ping passed so we are connected
	ret = findings.URL{URL: URL}

	return ret, errs
}
