package captcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go-visa-monitor/internal/config"
	"go-visa-monitor/internal/proxy" // Import proxy package
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Solver struct {
	apiKey string
	// Remove direct client, use proxy instead
}

type SolveResult struct {
	Text       string
	Cookies    []*http.Cookie
	JsessionID string
	Error      error
}

type TwoCaptchaResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

type SubmitResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

func NewSolver(apiKey string) *Solver {
	return &Solver{
		apiKey: apiKey,
		// No client here - we'll use proxy for each request
	}
}

func (s *Solver) Solve(ctx context.Context, embassyConfig config.EmbassyConfig) (*SolveResult, error) {
	log.Printf("🔐 Starting CAPTCHA solving for %s", embassyConfig.Name)

	// Step 1: Fetch CAPTCHA page WITH PROXY
	captchaImageData, cookies, jsessionid, err := s.fetchCaptchaImage(ctx, embassyConfig)
	if err != nil {
		return nil, fmt.Errorf("fetch CAPTCHA: %w", err)
	}

	// Step 2: Base64 encode
	captchaBase64 := base64.StdEncoding.EncodeToString(captchaImageData)

	// Step 3: Submit to 2Captcha (this doesn't need proxy)
	captchaID, err := s.submitTo2Captcha(ctx, captchaBase64)
	if err != nil {
		return nil, fmt.Errorf("submit to 2captcha: %w", err)
	}

	// Step 4: Poll for solution (this doesn't need proxy)
	solvedText, err := s.waitForSolution(ctx, captchaID)
	if err != nil {
		return nil, fmt.Errorf("wait for solution: %w", err)
	}

	log.Printf("✅ CAPTCHA solved successfully for %s", embassyConfig.Name)
	return &SolveResult{
		Text:       solvedText,
		Cookies:    cookies,
		JsessionID: jsessionid,
	}, nil
}

func (s *Solver) fetchCaptchaImage(ctx context.Context, embassy config.EmbassyConfig) ([]byte, []*http.Cookie, string, error) {
	log.Printf("📥 Fetching CAPTCHA page for %s...", embassy.Name)

	// USE PROXY for embassy requests
	client := proxy.NewProxiedClient()

	// Prepare form data
	formData := url.Values{
		"locationCode": {embassy.LocationCode},
		"realmId":      {embassy.RealmID},
		"categoryId":   {embassy.CategoryID},
	}

	// Create POST request
	req, err := http.NewRequestWithContext(ctx, "POST", embassy.URL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, nil, "", fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VisaMonitor/1.0)")

	// Execute request WITH PROXY
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, nil, "", fmt.Errorf("embassy returned status: %d %s", resp.StatusCode, resp.Status)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read response body: %w", err)
	}

	if len(body) == 0 {
		return nil, nil, "", fmt.Errorf("empty response from embassy")
	}

	log.Printf("✅ CAPTCHA page downloaded for %s (%d bytes)", embassy.Name, len(body))

	html := string(body)

	// Extract CAPTCHA image
	imageData, err := s.extractCaptchaFromHTML(html)
	if err != nil {
		return nil, resp.Cookies(), "", err
	}

	// Extract jsessionid from the form action
	jsessionid, err := s.extractJsessionID(html)
	if err != nil {
		return nil, resp.Cookies(), "", fmt.Errorf("extract jsessionid: %w", err)
	}

	// Log important cookies
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "KEKS" {
			log.Printf("🔍 KEKS cookie: %s", cookie.Value)
		}
	}

	return imageData, resp.Cookies(), jsessionid, nil
}

func (s *Solver) extractJsessionID(html string) (string, error) {
	re := regexp.MustCompile(`appointment_showMonth\.do;jsessionid=([A-F0-9]+)`)
	matches := re.FindStringSubmatch(html)

	if len(matches) >= 2 {
		jsessionid := matches[1]
		log.Printf("✅ Extracted jsessionid: %s", jsessionid)
		return jsessionid, nil
	}

	return "", fmt.Errorf("jsessionid not found in HTML")
}

func (s *Solver) extractCaptchaFromHTML(html string) ([]byte, error) {
	log.Printf("📄 Processing CAPTCHA HTML (%d bytes)", len(html))

	patterns := []string{
		`data:image/jpg;base64,([A-Za-z0-9+/=]+)`,
		`data:image/jpeg;base64,([A-Za-z0-9+/=]+)`,
		`data:image/jpg;base64,([^"'>]+)`,
		`src="data:image/jpg;base64,([^"]+)"`,
		`data:image/jpg;base64,([A-Za-z0-9+/]{20,})`,
	}

	for i, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)

		if len(matches) >= 2 {
			base64Data := matches[1]
			log.Printf("🔍 Found CAPTCHA with pattern %d", i+1)

			if len(base64Data) < 100 {
				log.Printf("⚠️ Base64 data seems too short: %d chars", len(base64Data))
				continue
			}

			imageData, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				log.Printf("❌ Base64 decode failed: %v", err)
				continue
			}

			log.Printf("✅ CAPTCHA image extracted (%d bytes)", len(imageData))
			return imageData, nil
		}
	}

	// Manual extraction fallback
	manualExtract, err := s.manualExtractCaptcha(html)
	if err == nil {
		return manualExtract, nil
	}

	return nil, fmt.Errorf("no CAPTCHA image found in HTML (tried %d patterns + manual)", len(patterns))
}

func (s *Solver) manualExtractCaptcha(html string) ([]byte, error) {
	startMarker := "data:image/jpg;base64,"
	startIdx := strings.Index(html, startMarker)
	if startIdx == -1 {
		return nil, fmt.Errorf("base64 marker not found")
	}

	startIdx += len(startMarker)
	endMarkers := []string{`"`, `'`, ` `, `>`, `</`}
	var endIdx int = len(html)

	for _, marker := range endMarkers {
		if idx := strings.Index(html[startIdx:], marker); idx != -1 && idx < endIdx {
			endIdx = idx
		}
	}

	base64Data := html[startIdx : startIdx+endIdx]
	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("manual decode failed: %v", err)
	}

	log.Printf("✅ Manual CAPTCHA extraction successful (%d bytes)", len(imageData))
	return imageData, nil
}

// 2Captcha API calls - these DON'T need proxies
func (s *Solver) submitTo2Captcha(ctx context.Context, base64Image string) (string, error) {
	apiURL := "http://2captcha.com/in.php"

	if base64Image == "" {
		return "", fmt.Errorf("empty CAPTCHA image")
	}
	if s.apiKey == "" {
		return "", fmt.Errorf("missing API key")
	}

	// Use direct client for 2Captcha API (no proxy needed)
	client := &http.Client{Timeout: 30 * time.Second}

	formData := url.Values{
		"key":    {s.apiKey},
		"method": {"base64"},
		"body":   {base64Image},
		"json":   {"1"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "VisaMonitor/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("2captcha API returned status: %d %s",
			resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	log.Printf("2Captcha submit response: %s", string(body))

	var result SubmitResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse JSON response: %w, body: %s", err, string(body))
	}

	switch result.Status {
	case 1:
		log.Printf("✅ CAPTCHA submitted successfully. ID: %s", result.Request)
		return result.Request, nil
	case 0:
		return "", fmt.Errorf("2captcha API error: %s", result.Request)
	default:
		return "", fmt.Errorf("unexpected 2captcha response: status=%d, request=%s",
			result.Status, result.Request)
	}
}

func (s *Solver) checkSolution(ctx context.Context, captchaID string) (text string, solved bool, err error) {
	apiURL := "http://2captcha.com/res.php"

	// Use direct client for 2Captcha API (no proxy needed)
	client := &http.Client{Timeout: 30 * time.Second}

	params := url.Values{
		"key":    {s.apiKey},
		"action": {"get"},
		"id":     {captchaID},
		"json":   {"1"},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return "", false, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("read response: %w", err)
	}

	log.Printf("2Captcha check response: %s", string(body))

	var result TwoCaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, fmt.Errorf("decode JSON: %w, body: %s", err, string(body))
	}

	switch {
	case result.Status == 1:
		return result.Request, true, nil
	case result.Status == 0 && result.Request == "CAPCHA_NOT_READY":
		return "", false, nil
	case result.Status == 0:
		return "", false, fmt.Errorf("2captcha API error: %s", result.Request)
	default:
		return "", false, fmt.Errorf("unexpected 2captcha response: status=%d, request=%s",
			result.Status, result.Request)
	}
}

func (s *Solver) waitForSolution(ctx context.Context, captchaID string) (string, error) {
	const maxAttempts = 30
	const pollInterval = 5 * time.Second

	log.Printf("⏳ Waiting for CAPTCHA solution (max %d attempts)...\n", maxAttempts)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			text, solved, err := s.checkSolution(ctx, captchaID)
			if err != nil {
				return "", err
			}
			if solved {
				log.Printf("✅ CAPTCHA solved: %s", text)
				return text, nil
			}

			if attempt < maxAttempts-1 {
				log.Printf("Attempt %d/%d: CAPTCHA not ready, waiting...", attempt+1, maxAttempts)
				time.Sleep(pollInterval)
			}
		}
	}

	return "", fmt.Errorf("CAPTCHA solving timeout after %d attempts", maxAttempts)
}
