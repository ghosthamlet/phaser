package subjack

import (
	"io/ioutil"
	"net/http"
	"time"
)

func get(url string, ssl bool, timeout int) (body []byte) {
	ret := []byte{}

	client := http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	res, err := client.Get(site(url, ssl))
	if err != nil {
		return ret
	}
	ret, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return []byte{}
	}
	return ret
}

func https(url string, ssl bool, timeout int) (body []byte) {
	newUrl := "https://" + url
	body = get(newUrl, ssl, timeout)

	return body
}

func site(url string, ssl bool) (site string) {
	site = "http://" + url
	if ssl {
		site = "https://" + url
	}

	return site
}
