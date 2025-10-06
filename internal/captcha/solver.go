package captcha

// imports

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go-visa-monitor/internal/config"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// declare types

type Solver struct {
	apiKey string
	client *http.Client
}

type SolveResult struct {
	Text       string
	Cookies    []*http.Cookie
	JsessionID string
	Error      error
}

type TwoCaptchaResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"` // The solved CAPTCHA text or error code
}

type SubmitResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"` // CAPTCHA ID or error message
}

// top level solver
func (s *Solver) Solve(ctx context.Context, embassyConfig config.EmbassyConfig) (*SolveResult, error) {
	// Step 1: Fetch CAPTCHA page
	captchaImageData, cookies, jsessionid, err := s.fetchCaptchaImage(ctx, embassyConfig)
	if err != nil {
		return nil, fmt.Errorf("fetch CAPTCHA: %w", err)
	}

	// Step 2: Base64 encode
	captchaBase64 := base64.StdEncoding.EncodeToString(captchaImageData)

	// Step 3: Submit to 2Captcha
	captchaID, err := s.submitTo2Captcha(ctx, captchaBase64)
	if err != nil {
		return nil, fmt.Errorf("submit to 2captcha: %w", err)
	}

	// Step 4: Poll for solution
	solvedText, err := s.waitForSolution(ctx, captchaID)
	if err != nil {
		return nil, fmt.Errorf("wait for solution: %w", err)
	}

	return &SolveResult{
		Text:       solvedText,
		Cookies:    cookies,
		JsessionID: jsessionid,
	}, nil
}

// Helper functions

func (s *Solver) fetchCaptchaImage(ctx context.Context, embassy config.EmbassyConfig) ([]byte, []*http.Cookie, string, error) {
	fmt.Printf("Step 1: Getting CAPTCHA page for %s...\n", embassy.Name)

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

	// Execute request
	resp, err := s.client.Do(req)
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

	fmt.Printf("✅ Page downloaded successfully for %s (%d bytes)\n", embassy.Name, len(body))

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

	// Debug: Log the KEKS cookie value
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "KEKS" {
			fmt.Printf("🔍 KEKS cookie value: %s\n", cookie.Value)
		}
	}

	return imageData, resp.Cookies(), jsessionid, nil
}

func (s *Solver) extractJsessionID(html string) (string, error) {
	// Look for: appointment_showMonth.do;jsessionid=XXXXXXXXXXXX
	re := regexp.MustCompile(`appointment_showMonth\.do;jsessionid=([A-F0-9]+)`)
	matches := re.FindStringSubmatch(html)

	if len(matches) >= 2 {
		jsessionid := matches[1]
		fmt.Printf("✅ Extracted jsessionid: %s\n", jsessionid)
		return jsessionid, nil
	}

	return "", fmt.Errorf("jsessionid not found in HTML")
}
func (s *Solver) extractCaptchaFromHTML(html string) ([]byte, error) {
	// ✅ REPLACE file saving with logging
	fmt.Printf("📄 CAPTCHA HTML received (%d bytes)\n", len(html))

	// Log a sample of the HTML for debugging
	sampleLength := min(500, len(html))
	fmt.Printf("🔍 HTML sample: %s\n", html[:sampleLength])

	// Try multiple regex patterns (same as before)
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
			fmt.Printf("🔍 Found CAPTCHA with pattern %d: %s\n", i+1, pattern)
			fmt.Printf("📏 Base64 data length: %d characters\n", len(base64Data))

			if len(base64Data) < 100 {
				fmt.Printf("⚠️ Base64 data seems too short: %d chars\n", len(base64Data))
				continue
			}

			// Try to decode
			imageData, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				fmt.Printf("❌ Base64 decode failed: %v\n", err)
				fmt.Printf("🔍 First 100 chars: %s\n", base64Data[:min(100, len(base64Data))])
				continue
			}

			fmt.Printf("✅ CAPTCHA image extracted (%d bytes)\n", len(imageData))

			// ✅ REMOVED file saving - just log success
			fmt.Printf("📸 CAPTCHA image ready for 2captcha\n")

			return imageData, nil
		}
	}

	// Manual extraction (same logic but without file ops)
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

	// Find where the base64 ends
	endMarkers := []string{`"`, `'`, ` `, `>`, `</`}
	var endIdx int = len(html)

	for _, marker := range endMarkers {
		if idx := strings.Index(html[startIdx:], marker); idx != -1 && idx < endIdx {
			endIdx = idx
		}
	}

	base64Data := html[startIdx : startIdx+endIdx]
	fmt.Printf("🔍 Manual extraction: %d chars\n", len(base64Data))

	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("manual decode failed: %v", err)
	}

	fmt.Printf("✅ Manual CAPTCHA extraction successful (%d bytes)\n", len(imageData))
	return imageData, nil
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Solver) submitTo2Captcha(ctx context.Context, base64Image string) (string, error) {
	apiURL := "http://2captcha.com/in.php"

	// Validate input
	if base64Image == "" {
		return "", fmt.Errorf("empty CAPTCHA image")
	}
	if s.apiKey == "" {
		return "", fmt.Errorf("missing API key")
	}

	// Prepare form data (matches your bash script)
	formData := url.Values{
		"key":    {s.apiKey},
		"method": {"base64"},
		"body":   {base64Image},
		"json":   {"1"},
	}

	// Create POST request with context
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "VisaMonitor/1.0")

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("2captcha API returned status: %d %s",
			resp.StatusCode, resp.Status)
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	// Debug logging
	fmt.Printf("2Captcha submit response: %s\n", string(body))

	var result SubmitResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse JSON response: %w, body: %s", err, string(body))
	}

	// Handle response
	switch result.Status {
	case 1:
		// Success - return CAPTCHA ID for polling
		fmt.Printf("✅ CAPTCHA submitted successfully. ID: %s\n", result.Request)
		return result.Request, nil

	case 0:
		// Error from 2Captcha
		return "", fmt.Errorf("2captcha API error: %s", result.Request)

	default:
		return "", fmt.Errorf("unexpected 2captcha response: status=%d, request=%s",
			result.Status, result.Request)
	}
}

func (s *Solver) checkSolution(ctx context.Context, captchaID string) (text string, solved bool, err error) {
	apiURL := "http://2captcha.com/res.php"

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

	resp, err := s.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body first
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("read response: %w", err)
	}

	// Debug logging (optional)
	fmt.Printf("2Captcha response: %s\n", string(body))

	var result TwoCaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, fmt.Errorf("decode JSON: %w, body: %s", err, string(body))
	}

	// Handle different response cases
	switch {
	case result.Status == 1:
		// Success!
		return result.Request, true, nil

	case result.Status == 0 && result.Request == "CAPCHA_NOT_READY":
		// Still processing, not an error
		return "", false, nil

	case result.Status == 0:
		// Actual error from 2Captcha
		return "", false, fmt.Errorf("2captcha API error: %s", result.Request)

	default:
		return "", false, fmt.Errorf("unexpected 2captcha response: status=%d, request=%s",
			result.Status, result.Request)
	}
}

func (s *Solver) waitForSolution(ctx context.Context, captchaID string) (string, error) {
	const maxAttempts = 30 // Fixed: should be 30 like your bash script
	const pollInterval = 5 * time.Second

	fmt.Printf("⏳ Waiting for CAPTCHA solution (max %d attempts)...\n", maxAttempts)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			// Check if solution is ready
			text, solved, err := s.checkSolution(ctx, captchaID)
			if err != nil {
				return "", err
			}
			if solved {
				fmt.Printf("✅ CAPTCHA solved: %s\n", text)
				return text, nil
			}

			// Not ready yet, wait and retry
			if attempt < maxAttempts-1 { // Don't sleep on last attempt
				fmt.Printf("Attempt %d/%d: CAPTCHA not ready, waiting...\n", attempt+1, maxAttempts)
				time.Sleep(pollInterval)
			}
		}
	}

	return "", fmt.Errorf("CAPTCHA solving timeout after %d attempts", maxAttempts)
}

// Add this constructor function
func NewSolver(apiKey string) *Solver {
	return &Solver{
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}
