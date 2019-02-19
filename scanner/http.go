package scanner

import (
	"net/http"
	"time"
)

func createHTTPClient() *http.Client {
	client := &http.Client{
		Timeout: time.Second * 3,
	}
	return client
}
