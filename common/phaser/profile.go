package phaser

type Profile struct {
	HTTP       ProfileHTTPConfig `json:"http" sane:"http"`
	Subdomains bool              `json:"subdomains" sane:"subdomains"` // enable subdomains scan
	Modules    ProfileModules    `json:"modules" sane:"modules"`
}

type ProfileModules = map[string]ProfileModuleOptions
type ProfileModuleOptions = map[string]interface{}

type ProfileHTTPConfig struct {
	UserAgent string `json:"user_agent" sane:"user_agent"` // default useragent to use
}
