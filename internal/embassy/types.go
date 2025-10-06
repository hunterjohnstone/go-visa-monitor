package embassy

import (
	"go-visa-monitor/internal/config"
	"net/http"
	"time"
)

type EmbassyClient struct {
	config     config.EmbassyConfig
	httpClient *http.Client
}

type CheckResult struct {
	Embassy     string    // Embassy name (e.g., "Windhoek")
	Available   bool      // Whether appointments are available
	Error       error     // Any error that occurred during checking
	CaptchaText string    // The solved CAPTCHA text (for debugging)
	RawHTML     string    // Raw HTML response (optional, for analysis)
	Timestamp   time.Time // When the check was performed
}
