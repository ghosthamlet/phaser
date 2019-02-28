package jetty

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type CVE_2015_2080 struct{}

func (CVE_2015_2080) Name() string {
	return "http/jetty/cve_2015_2080"
}

func (CVE_2015_2080) Description() string {
	return "Check for CVE-2015-2080 (a.k.a. Jetleak)"
}

func (CVE_2015_2080) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (CVE_2015_2080) Version() string {
	return "0.1.0"
}

const JETLEAK_REGEXP = "^jetty\\(9\\.2\\.(3|4|5|6|7|8).*\\)$|^jetty\\(9\\.3\\.0\\.(m0|m1).*\\)$"

func (CVE_2015_2080) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
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
	res.Body.Close()
	server := strings.ToLower(strings.TrimSpace(res.Header.Get("server")))

	matched, err := regexp.MatchString(JETLEAK_REGEXP, server)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	if matched {
		ret = findings.URL{URL: URL}
	}

	return ret, errs
}

// package scan

// import (
// 	"fmt"
// 	"net/http"
// 	"regexp"
// 	"strings"
// )

// const JETLEAK_REGEXP = "^jetty\\(9\\.2\\.(3|4|5|6|7|8).*\\)$|^jetty\\(9\\.3\\.0\\.(m0|m1).*\\)$"

// type CVE_2015_2080_Finding struct {
// 	Location Location `json:"location"`
// 	// Response string   `json:"response"`
// 	// Request  string   `json:"request"`
// }

// type CVE_2015_2080_Check struct {
// 	Findings []CVE_2015_2080_Finding `json:"findings"`
// 	Errors   []CheckError            `json:"errors"`
// }

// // https://github.com/GDSSecurity/Jetleak-Testing-Script
// // CVE-2015-2080
// // jetleak
// func (scan *Scan) CVE_2015_2080(target Target) CVE_2015_2080_Check {
// 	ret := CVE_2015_2080_Check{
// 		Findings: []CVE_2015_2080_Finding{},
// 		Errors:   []CheckError{},
// 	}

// 	// fmt.Println("JETLEAK")

// 	// req := fasthttp.AcquireRequest()
// 	// URI := fmt.Sprintf("http://%s:8081/", target.Target)
// 	// fmt.Println("URI", URI)
// 	// req.SetRequestURI(URI)
// 	// req.Header.SetMethodBytes([]byte("POST"))
// 	// // req.Header.Reset()
// 	// // req.Header.Set("Referer", "\000")
// 	// req.Header.SetReferer("\000")
// 	// req.Header.Set("Content-Type", "application/json")
// 	// req.Header.Set("User-Agent", scan.Profile.UserAgent)
// 	// resp := fasthttp.AcquireResponse()
// 	// client := &fasthttp.Client{}
// 	// client.Do(req, resp)
// 	// fmt.Println(resp.StatusCode())
// 	// fmt.Println(string(resp.Header.Header()))
// 	// fmt.Println(string(resp.Header.String()))
// 	// fmt.Println(string(req.String()))
// 	// fmt.Println(string(resp.String()))
// 	// body := resp.Body()
// 	// println(string(bodyBytes))
// 	URL := fmt.Sprintf("http://%s", target.Host)
// 	req, err := http.NewRequest("POST", URL, nil)
// 	if err != nil {
// 		return ret
// 	}
// 	// req.Header
// 	req.Header.Set("User-Agent", scan.Profile.UserAgent)
// 	// jeyleak test
// 	// req.Header.
// 	// req.Header.Set("Referer", "\x00")
// 	// req.Header.Add("Referer", "\x00")
// 	res, err := scan.client.Do(req)
// 	if err != nil {
// 		ret.Errors = append(ret.Errors, formatError(err.Error(), target.Host, target.Type, nil))
// 		return ret
// 	}
// 	// request, _ := httputil.DumpRequestOut(req, true)
// 	// response, _ := httputil.DumpResponse(res, true)
// 	res.Body.Close()
// 	server := strings.ToLower(strings.TrimSpace(res.Header.Get("server")))
// 	// fmt.Println(res.Header.Get("server"))
// 	// body, err := ioutil.ReadAll(res.Body)
// 	// if err != nil {
// 	// 	fmt.Println("ERR2", err)
// 	// 	return ret
// 	// }
// 	// res.Body.Close()
// 	// bodyStr := string(body)
// 	// fmt.Println("JETLEAK")

// 	// fmt.Println(bodyStr)

// 	// 	python := `
// 	// import http.client, urllib, ssl, string, sys, getopt
// 	//
// 	// if len(sys.argv) < 3:
// 	//     print("Usage: jetleak.py [url] [port]")
// 	//     sys.exit(1)
// 	//
// 	// url = urllib.parse.urlparse(sys.argv[1])
// 	// if url.scheme == '' and url.netloc == '':
// 	//     print("Error: Invalid URL Entered.")
// 	//     sys.exit(1)
// 	//
// 	// port = sys.argv[2]
// 	//
// 	// conn = None
// 	//
// 	// if url.scheme == "https":
// 	//     context = ssl.SSLContext()
// 	//     context.verify_mode = ssl.CERT_NONE
// 	//     # context.check_hostname = False
// 	//     conn = http.client.HTTPSConnection(url.netloc,  port=port, context=context)
// 	// elif url.scheme == "http":
// 	//     conn = http.client.HTTPConnection(url.netloc, port=port)
// 	// else:
// 	//     print("Error: Only 'http' or 'https' URL Schemes Supported")
// 	//     sys.exit(1)
// 	//
// 	// x = "\x00"
// 	// headers = {"Referer": x}
// 	// conn.request("POST", "/", "", headers)
// 	// r1 = conn.getresponse()
// 	// if (r1.status == 400 and ("Illegal character 0x0 in state" in r1.reason)):
// 	//     print("VULNERABLE")
// 	// else:
// 	//     print("NOT vulnerable")
// 	// `
// 	// 	tmpfile, err := ioutil.TempFile(os.TempDir(), "beam")
// 	// 	if err != nil {
// 	// 		error := err.Error()
// 	// 		ret.Error = &error
// 	// 		return ret
// 	// 	}
// 	//
// 	// 	// defer os.Remove(tmpfile.Name())
// 	// 	_, err = tmpfile.Write([]byte(python))
// 	// 	if err != nil {
// 	// 		error := err.Error()
// 	// 		ret.Error = &error
// 	// 		return ret
// 	// 	}
// 	// 	tmpfile.Close()
// 	// 	command := "python3"
// 	// 	commandArgs := []string{tmpfile.Name(), "http://" + target.Target, "80"}
// 	// 	// fmt.Println(command, commandArgs)
// 	//
// 	// 	out, err := exec.Command(command, commandArgs...).Output()
// 	// 	if err != nil {
// 	// 		error := err.Error()
// 	// 		ret.Error = &error
// 	// 		return ret
// 	// 	}
// 	//
// 	// 	outStr := string(out)
// 	//
// 	matched, err := regexp.MatchString(JETLEAK_REGEXP, server)
// 	if err != nil {
// 		ret.Errors = append(ret.Errors, formatError(err.Error(), target.Host, target.Type, nil))
// 		return ret
// 	}

// 	if matched == true {
// 		finding := CVE_2015_2080_Finding{
// 			Location: Location{
// 				Resource: URL,
// 				Type:     "url",
// 			},
// 			// Request:  string(request),
// 			// Response: string(response),
// 		}
// 		ret.Findings = append(ret.Findings, finding)
// 	}
// 	return ret
// }
