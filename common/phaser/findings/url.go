package findings

type URL struct {
	URL string `json:"url"`
}

type URLCredentials struct {
	URL string `json:"url"`
	Credentials
}

type URLResponse struct {
	URL      string `json:"url"`
	Response string `json:"response"`
}
