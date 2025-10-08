package config

type Config struct {
	CaptchaAPIKey  string
	SendGridAPIKey string
	DatabaseURL    string
	FrontendURL    string
	ApiKey         string
	ProxyUrls      []string
	CheckInterval  int
	MaxConcurrency int
}

type EmbassyConfig struct {
	Name         string
	LocationCode string
	RealmID      string
	CategoryID   string
	URL          string
}
