package config

type Config struct {
	CaptchaAPIKey  string
	SendGridAPIKey string
	DatabaseURL    string
	FrontendURL    string // Add this for unsubscribe links
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
