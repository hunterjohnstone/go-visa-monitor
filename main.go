package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go-visa-monitor/internal/captcha"
	"go-visa-monitor/internal/config"
	"go-visa-monitor/internal/embassy"
	"go-visa-monitor/internal/notifier"
	"go-visa-monitor/internal/storage"
)

type Monitor struct {
	config        *config.Config
	captchaSolver *captcha.Solver
	notifier      *notifier.EmailNotifier
	database      *storage.Database
	embassies     []config.EmbassyConfig
}

func NewMonitor(cfg *config.Config) *Monitor {
	captchaSolver := captcha.NewSolver(cfg.CaptchaAPIKey)
	notifier := notifier.NewEmailNotifier(cfg.SendGridAPIKey)
	database := storage.NewDatabase(cfg.DatabaseURL)
	embassies := getEmbassiesToMonitor()

	// Test database connection
	if err := database.HealthCheck(); err != nil {
		log.Printf("⚠️ Database health check failed: %v", err)
		log.Printf("⚠️ Continuing with fallback email mode")
	}

	return &Monitor{
		config:        cfg,
		captchaSolver: captchaSolver,
		notifier:      notifier,
		database:      database,
		embassies:     embassies,
	}
}

func getEmbassiesToMonitor() []config.EmbassyConfig {
	var embassies []config.EmbassyConfig
	for _, embassy := range embassy.Embassies {
		embassies = append(embassies, embassy)
	}
	return embassies
}
func (m *Monitor) Run(ctx context.Context) {
	log.Println("🚀 Running single embassy check...")
	m.checkAllEmbassies(ctx)
}

func (m *Monitor) checkAllEmbassies(ctx context.Context) {
	log.Printf("🔍 Checking %d embassies for appointments...", len(m.embassies))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.config.MaxConcurrency)

	results := make(chan *embassy.CheckResult, len(m.embassies))

	for _, embassyConfig := range m.embassies {
		wg.Add(1)
		go func(config config.EmbassyConfig) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := m.checkEmbassy(ctx, config)
			results <- result
		}(embassyConfig)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		m.handleResult(result)
	}

	log.Println("✅ Completed embassy check cycle")
}

func (m *Monitor) handleResult(result *embassy.CheckResult) {
	if result.Error != nil {
		log.Printf("❌ Error checking %s: %v", result.Embassy, result.Error)
		return
	}

	if result.Available {
		log.Printf("🚨🚨🚨 APPOINTMENTS AVAILABLE in %s! 🚨🚨🚨", result.Embassy)
		m.sendAlerts(result)
	} else {
		log.Printf("✅ No appointments in %s (checked at %s)", result.Embassy, result.Timestamp.Format("15:04:05"))
	}
}

func (m *Monitor) sendAlerts(result *embassy.CheckResult) {
	log.Printf("🚨 Sending alerts for %s appointments!", result.Embassy)

	var subscribers []string
	var err error

	subscribers, err = m.database.GetSubscriberEmails()
	if err != nil {
		log.Printf("❌ Failed to fetch subscribers from database: %v", err)
		subscribers = m.getFallbackEmails()
	}

	if len(subscribers) == 0 {
		log.Printf("⚠️ No subscribers found, using fallback emails")
		subscribers = m.getFallbackEmails()
	}

	log.Printf("📧 Sending alerts to %d subscribers", len(subscribers))

	successCount := 0
	for _, email := range subscribers {
		err := m.notifier.SendAppointmentAlert(email, result.Embassy, m.config.FrontendURL)
		if err != nil {
			log.Printf("❌ Failed to send alert to %s: %v", email, err)
		} else {
			log.Printf("✅ Alert sent to: %s", email)
			successCount++
		}
		time.Sleep(1 * time.Second)
	}

	log.Printf("📧 Successfully sent %d/%d alerts for %s", successCount, len(subscribers), result.Embassy)
}

func (m *Monitor) getFallbackEmails() []string {
	testEmail := os.Getenv("TEST_EMAIL")
	if testEmail != "" {
		return []string{testEmail}
	}
	return []string{"hunterjohnst1@gmail.com"}
}

func (m *Monitor) debugAnalysis(html string) {
	log.Printf("Content analysis:")
	patterns := []string{"termin", "appointment", "available", "verfügbar"}

	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(html), strings.ToLower(pattern)) {
			lines := strings.Split(html, "\n")
			for i, line := range lines {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					log.Printf("  Found '%s': %s", pattern, strings.TrimSpace(line))
					if i >= 3 {
						break
					}
				}
			}
		}
	}
}

func (m *Monitor) checkEmbassy(ctx context.Context, embassyConfig config.EmbassyConfig) *embassy.CheckResult {
	log.Printf("Checking %s embassy...", embassyConfig.Name)

	// Try up to 3 times if CAPTCHA fails
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("🔄 CAPTCHA attempt %d/%d for %s", attempt, maxRetries, embassyConfig.Name)
			// Small delay between retries
			time.Sleep(2 * time.Second)
		}

		solveResult, err := m.captchaSolver.Solve(ctx, embassyConfig)
		if err != nil {
			log.Printf("❌ CAPTCHA failed on attempt %d: %v", attempt, err)
			if attempt == maxRetries {
				return &embassy.CheckResult{
					Embassy:   embassyConfig.Name,
					Error:     fmt.Errorf("CAPTCHA failed after %d attempts: %w", maxRetries, err),
					Timestamp: time.Now(),
				}
			}
			continue
		}

		// cookies to appointment check
		available, err := m.checkAppointments(ctx, embassyConfig, solveResult.Text, solveResult.Cookies, solveResult.JsessionID)
		if err != nil {
			if strings.Contains(err.Error(), "CAPTCHA failed") {
				log.Printf("❌ CAPTCHA rejected on attempt %d: %v", attempt, err)
				if attempt == maxRetries {
					return &embassy.CheckResult{
						Embassy:   embassyConfig.Name,
						Error:     fmt.Errorf("CAPTCHA rejected after %d attempts: %w", maxRetries, err),
						Timestamp: time.Now(),
					}
				}
				continue
			}
			return &embassy.CheckResult{
				Embassy:   embassyConfig.Name,
				Error:     fmt.Errorf("appointment check failed: %w", err),
				Timestamp: time.Now(),
			}
		}

		return &embassy.CheckResult{
			Embassy:     embassyConfig.Name,
			Available:   available,
			Timestamp:   time.Now(),
			CaptchaText: solveResult.Text,
		}
	}

	return &embassy.CheckResult{
		Embassy:   embassyConfig.Name,
		Error:     fmt.Errorf("max retries exceeded"),
		Timestamp: time.Now(),
	}
}

func (m *Monitor) checkAppointments(ctx context.Context, embassyConfig config.EmbassyConfig, captchaText string, cookies []*http.Cookie, jsessionid string) (bool, error) {
	log.Printf("Step 5: Checking appointments for %s...", embassyConfig.Name)

	// Use the URL with jsessionid!
	appointmentURL := fmt.Sprintf("%s;jsessionid=%s", embassyConfig.URL, jsessionid)

	// Prepare form data using url.Values for proper encoding
	formData := url.Values{
		"captchaText":                  {captchaText},
		"rebooking":                    {"false"},
		"locationCode":                 {embassyConfig.LocationCode},
		"realmId":                      {embassyConfig.RealmID},
		"categoryId":                   {embassyConfig.CategoryID},
		"action:appointment_showMonth": {"Weiter"},
	}.Encode()

	fmt.Printf("🔍 CAPTCHA text being sent: %s\n", captchaText)

	// appointment check request
	html, err := m.makeAppointmentRequest(ctx, appointmentURL, formData, cookies)
	if err != nil {
		return false, fmt.Errorf("appointment request failed: %w", err)
	}

	// Analyze
	available, err := m.analyzeAppointmentResults(html)
	if err != nil {
		return false, err
	}

	if available {
		log.Printf("🚨 POSSIBLE APPOINTMENTS DETECTED in %s!", embassyConfig.Name)
		m.debugAnalysis(html)
		// m.saveAppointmentResults(html, embassyConfig.Name)
	} else {
		log.Printf("No appointments available in %s", embassyConfig.Name)
	}

	return available, nil
}

func (m *Monitor) makeAppointmentRequest(ctx context.Context, requestURL, formData string, cookies []*http.Cookie) (string, error) {
	// make HTTP client cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("create cookie jar: %w", err)
	}

	// Set the cookies
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	jar.SetCookies(u, cookies)

	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	fmt.Printf("🔍 Sending POST to: %s\n", requestURL)
	fmt.Printf("🔍 Form data: %s\n", formData)
	fmt.Printf("🔍 Cookies: %d cookies\n", len(cookies))
	for i, cookie := range cookies {
		fmt.Printf("   Cookie %d: %s=%s\n", i+1, cookie.Name, cookie.Value)
	}

	//POST request
	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBufferString(formData))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VisaMonitor/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("🔍 Response status: %d %s\n", resp.StatusCode, resp.Status)
	fmt.Printf("🔍 Response cookies: %d cookies\n", len(resp.Cookies()))

	// check status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("embassy returned status: %d %s", resp.StatusCode, resp.Status)
	}

	// Read response bod
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if len(body) == 0 {
		return "", fmt.Errorf("empty response from embassy")
	}

	log.Printf("✅ Got appointment results (%d bytes)", len(body))

	// Save the response for debugging
	debugFilename := "debug_appointment_response.html"
	if err := os.WriteFile(debugFilename, body, 0644); err == nil {
		fmt.Printf("📄 Saved appointment response: %s\n", debugFilename)
	}

	return string(body), nil
}

func (m *Monitor) analyzeAppointmentResults(html string) (bool, error) {
	// Negative patterns from your bash script
	negativePatterns := []string{
		"keine Termine",
		"leider keine",
		"Es sind zur Zeit",
		"nicht verfügbar",
		"no appointments",
		"Unfortunately, there are",
		"currently no",
		"at this time",
		"will be made available",
		"freigeschaltet",
		"regelmäßigen Abständen",
	}

	// If CAPTCHA form appears, solution was wrong
	if strings.Contains(html, "captchaText") {
		// Check if there's an error message about the CAPTCHA
		if strings.Contains(strings.ToLower(html), "falsch") || strings.Contains(strings.ToLower(html), "wrong") {
			return false, fmt.Errorf("CAPTCHA failed - solution was wrong (explicit error)")
		}
		return false, fmt.Errorf("CAPTCHA failed - solution was wrong")
	}

	// Check for negative indicators
	for _, pattern := range negativePatterns {
		if strings.Contains(strings.ToLower(html), strings.ToLower(pattern)) {
			log.Printf("✅ Found negative indicator: '%s'", pattern)
			return false, nil // No appointments
		}
	}

	// No negative patterns found - possible appointments!
	log.Printf("🚨 No negative indicators found - appointments might be available!")
	return true, nil
}

func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open .env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			value = strings.Trim(value, `"'`)

			// Set environment variable
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

func main() {
	// Load .env file first
	if err := loadEnvFile(".env"); err != nil {
		log.Printf("⚠️ Could not load .env file: %v", err)
		log.Printf("⚠️ Continuing with system environment variables only")
	}

	cfg := &config.Config{
		CaptchaAPIKey:  os.Getenv("CAPTCHA_API_KEY"),
		SendGridAPIKey: os.Getenv("SENDGRID_API_KEY"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		FrontendURL:    os.Getenv("FRONTEND_URL"),
		CheckInterval:  5,
		MaxConcurrency: 3,
	}

	if cfg.CaptchaAPIKey == "" {
		log.Fatal("❌ CAPTCHA_API_KEY environment variable is required")
	}

	monitor := NewMonitor(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v, shutting down...", sig)
		cancel()
	}()

	monitor.Run(ctx)
	log.Println("Monitor stopped gracefully")
}
