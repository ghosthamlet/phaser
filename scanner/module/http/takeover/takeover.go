package takeover

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type Takeover struct{}

func (Takeover) Name() string {
	return "http/takeover"
}

func (Takeover) Description() string {
	return "Check subdomain takeover"
}

func (Takeover) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (Takeover) Version() string {
	return "0.1.0"
}

type VulnerableURL struct {
	URL     string `json:"url"`
	Service string `json:"service"`
}

func (Takeover) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result
	protocol := "http"
	service := ""

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

	// First round
	fingerprints := map[string]string{
		"ERROR: The request could not be satisfied":                                                  "AWS CLOUDFRONT",
		"Fastly error: unknown domain":                                                               "FASTLY",
		"There isn't a Github Pages site here.":                                                      "GITHUB",
		"herokucdn.com/error-pages/no-such-app.html":                                                 "HEROKU",
		"The gods are wise, but do not know of the site which you seek.":                             "PANTHEON",
		"Whatever you were looking for doesn't currently exist at this address.":                     "TUMBLR",
		"Do you want to register":                                                                    "WORDPRESS",
		"Sorry, We Couldn't Find That Page":                                                          "DESK",
		"Help Center Closed":                                                                         "ZENDESK",
		"Oops - We didn't find your site.":                                                           "TEAMWORK",
		"We could not find what you're looking for.":                                                 "HELPJUICE",
		"No settings were found for this company:":                                                   "HELPSCOUT",
		"The specified bucket does not exist":                                                        "AWS S3",
		"The thing you were looking for is no longer here, or never was":                             "GHOST",
		"<title>404 &mdash; File not found</title>":                                                  "CARGO",
		"The feed has not been found.":                                                               "FEEDPRESS",
		"Sorry, this shop is currently unavailable.":                                                 "SHOPIFY",
		"You are being <a href=\"https://www.statuspage.io\">redirected":                             "STATUSPAGE",
		"This UserVoice subdomain is currently available!":                                           "USERVOICE",
		"project not found":                                                                          "SURGE",
		"Unrecognized domain <strong>":                                                               "MASHERY",
		"Repository not found":                                                                       "BITBUCKET",
		"The requested URL was not found on this server.":                                            "UNBOUNCE",
		"This page is reserved for artistic dogs.":                                                   "INTERCOM",
		"<h1 class=\"headline\">Uh oh. That page doesn’t exist.</h1>":                                "INTERCOM",
		"<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>": "WEBFLOW",
		"Not found": "MAILERLITE",
		"<h1>The page you were looking for doesn't exist.</h1>":                                   "KAJABI",
		"You may have mistyped the address or the page may have moved.":                           "THINKIFIC",
		"<h1>Error 404: Page Not Found</h1>":                                                      "TAVE",
		"https://www.wishpond.com/404?campaign=true":                                              "WISHPOND",
		"Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.": "AFTERSHIP",
		"There is no portal here ... sending you back to Aha!":                                    "AHA",
		"to target URL: <a href=\"https://tictail.com":                                            "TICTAIL",
		"Start selling on Tictail.":                                                               "TICTAIL",
		"<p class=\"bc-gallery-error-code\">Error Code: 404</p>":                                  "BRIGHTCOVE",
		"<h1>Oops! We couldn&#8217;t find that page.</h1>":                                        "BIGCARTEL",
		"alt=\"LIGHTTPD - fly light.\"":                                                           "ACTIVECAMPAIGN",
		"Double check the URL or <a href=\"mailto:help@createsend.com":                            "CAMPAIGNMONITOR",
		"The site you are looking for could not be found.":                                        "ACQUIA",
		"If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz": "PROPOSIFY",
		"We can't find this <a href=\"https://simplebooklet.com":                                  "SIMPLEBOOKLET",
		"With GetResponse Landing Pages, lead generation has never been easier":                   "GETRESPONSE",
		"Looks like you've traveled too far into cyberspace.":                                     "VEND",
		"is not a registered InCloud YouTrack.":                                                   "JETBRAINS",
		"The page you're looking for is no longer available.":                                     "INSTAPAGE",
	}

	for f, _ := range fingerprints {
		if bytes.Contains(body, []byte(f)) {
			service = fingerprints[f]
			break
		}
	}

	// 2nd round - Ruling out false positives.
	switch service {
	case "INSTAPAGE":
		if !bytes.Contains(body, []byte("Looks Like You're Lost")) {
			service = ""
		}
	case "CARGO":
		if !bytes.Contains(body, []byte("cargocollective.com")) {
			service = ""
		}
	case "KAJABI":
		if !bytes.Contains(body, []byte("Use title if it's in the page YAML frontmatter")) {
			service = ""
		}
	case "THINKIFIC":
		if !bytes.Contains(body, []byte("iVBORw0KGgoAAAANSUhEUgAAAf")) {
			service = ""
		}
	case "TAVE":
		if !bytes.Contains(body, []byte("tave.com")) {
			service = ""
		}
	case "PROPOSIFY":
		if !bytes.Contains(body, []byte("The page you requested was not found.")) {
			service = ""
		}
	case "MAILERLITE":
		size := len(body)
		if size != 9 {
			service = ""
		}
	case "ACTIVECAMPAIGN":
		size := len(body)
		if size != 844 {
			service = ""
		}
	}

	if service != "" {
		ret = VulnerableURL{
			URL:     URL,
			Service: service,
		}
	}

	return ret, errs
}
