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
	"go-visa-monitor/internal/proxy" // Add proxy import
	"go-visa-monitor/internal/storage"

	"github.com/aws/aws-lambda-go/lambda"
)

func BatchHandler(ctx context.Context) (string, error) {
	log.Println("📦 Starting BATCH notifier (free users only)...")

	// Log proxy status at startup
	proxyCount := proxy.GetProxyCount()
	if proxyCount > 0 {
		log.Printf("🎯 Using %d proxies for requests", proxyCount)
	} else {
		log.Printf("⚠️ No proxies configured - using direct connections")
	}

	cfg := &config.Config{
		CaptchaAPIKey:  os.Getenv("CAPTCHA_API_KEY"),
		SendGridAPIKey: os.Getenv("SENDGRID_API_KEY"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		FrontendURL:    os.Getenv("FRONTEND_URL"),
		CheckInterval:  5,
		MaxConcurrency: 3,
	}

	monitor := NewMonitor(cfg)
	monitor.RunBatchCheck(ctx)

	return "Batch check completed", nil
}

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
	database := storage.NewDatabase(cfg.DatabaseURL, cfg.ApiKey)

	var embassies []config.EmbassyConfig
	for _, embassy := range embassy.Embassies {
		embassies = append(embassies, embassy)
	}

	return &Monitor{
		config:        cfg,
		captchaSolver: captchaSolver,
		notifier:      notifier,
		database:      database,
		embassies:     embassies,
	}
}

func (m *Monitor) RunBatchCheck(ctx context.Context) {
	log.Println("🔍 Checking embassies for BATCH alerts (free users only)...")

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
		m.handleBatchResult(result)
	}
}

func (m *Monitor) handleBatchResult(result *embassy.CheckResult) {
	if result.Error != nil {
		log.Printf("❌ Error checking %s: %v", result.Embassy, result.Error)
		return
	}

	if result.Available {
		log.Printf("🚨 APPOINTMENTS AVAILABLE in %s! Sending BATCH alerts", result.Embassy)
		m.SendBatchAlerts(result)
	} else {
		log.Printf("✅ No appointments in %s", result.Embassy)
	}
}

func (m *Monitor) SendBatchAlerts(result *embassy.CheckResult) {
	location := m.getLocationFromEmbassy(result.Embassy)
	log.Printf("📦 Sending BATCH alerts for %s appointments (location: %s)!", result.Embassy, location)

	subscribers, err := m.database.GetSubscribersByLocationAndTier(location, "free")
	if err != nil {
		log.Printf("❌ Failed to fetch free subscribers for %s: %v", location, err)
		return
	}

	if len(subscribers) == 0 {
		log.Printf("ℹ️ No free subscribers found for %s", location)
		return
	}

	log.Printf("📧 Sending batch alerts to %d free subscribers in %s", len(subscribers), location)

	successCount := 0
	for _, email := range subscribers {
		err := m.notifier.SendAppointmentAlert(email, result.Embassy, m.config.FrontendURL)
		if err != nil {
			log.Printf("❌ Failed to send batch alert to %s: %v", email, err)
		} else {
			log.Printf("✅ Batch alert sent to: %s", email)
			successCount++
		}
		time.Sleep(1 * time.Second)
	}

	log.Printf("📧 Successfully sent %d/%d batch alerts for %s", successCount, len(subscribers), result.Embassy)
}

func (m *Monitor) getLocationFromEmbassy(embassyName string) string {
	locationMap := map[string]string{
		"Windhoek":  "windhoek",
		"New Delhi": "newdelhi",
		"Istanbul":  "istanbul",
		"Moscow":    "moscow",
	}

	if location, exists := locationMap[embassyName]; exists {
		return location
	}

	lowerEmbassyName := strings.ToLower(embassyName)
	for key, location := range locationMap {
		if strings.Contains(lowerEmbassyName, strings.ToLower(key)) {
			log.Printf("🔍 Matched embassy '%s' to location '%s' via partial match", embassyName, location)
			return location
		}
	}

	log.Printf("⚠️ No location mapping found for embassy: %s", embassyName)
	return "windhoek"
}

func (m *Monitor) checkEmbassy(ctx context.Context, embassyConfig config.EmbassyConfig) *embassy.CheckResult {
	log.Printf("Checking %s embassy...", embassyConfig.Name)

	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("🔄 CAPTCHA attempt %d/%d for %s", attempt, maxRetries, embassyConfig.Name)
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

	appointmentURL := fmt.Sprintf("%s;jsessionid=%s", embassyConfig.URL, jsessionid)

	formData := url.Values{
		"captchaText":                  {captchaText},
		"rebooking":                    {"false"},
		"locationCode":                 {embassyConfig.LocationCode},
		"realmId":                      {embassyConfig.RealmID},
		"categoryId":                   {embassyConfig.CategoryID},
		"action:appointment_showMonth": {"Weiter"},
	}.Encode()

	fmt.Printf("🔍 CAPTCHA text being sent: %s\n", captchaText)

	html, err := m.makeAppointmentRequest(ctx, appointmentURL, formData, cookies)
	if err != nil {
		return false, fmt.Errorf("appointment request failed: %w", err)
	}

	available, err := m.analyzeAppointmentResults(html)
	if err != nil {
		return false, err
	}

	if available {
		log.Printf("🚨 POSSIBLE APPOINTMENTS DETECTED in %s!", embassyConfig.Name)
		m.debugAnalysis(html)
	} else {
		log.Printf("No appointments available in %s", embassyConfig.Name)
	}

	return available, nil
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

// UPDATED: Use proxy for appointment requests
func (m *Monitor) makeAppointmentRequest(ctx context.Context, requestURL, formData string, cookies []*http.Cookie) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("create cookie jar: %w", err)
	}

	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	jar.SetCookies(u, cookies)

	// USE PROXY: Get a proxied client instead of direct connection
	client := proxy.NewProxiedClient()

	log.Printf("🔍 Sending POST to: %s", u.Host)
	log.Printf("🔍 Cookies: %d cookies", len(cookies))

	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBufferString(formData))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VisaMonitor/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("🔍 Response status: %d %s", resp.StatusCode, resp.Status)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("embassy returned status: %d %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if len(body) == 0 {
		return "", fmt.Errorf("empty response from embassy")
	}

	log.Printf("✅ Got appointment results (%d bytes)", len(body))
	return string(body), nil
}

func main() {
	if os.Getenv("LOCAL_DEV") == "true" {
		runLocal()
	} else {
		lambda.Start(BatchHandler)
	}
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, `"'`)
			os.Setenv(key, value)
		}
	}
	return scanner.Err()
}

func runLocal() {
	// Load .env file first
	if err := loadEnvFile(".env"); err != nil {
		log.Printf("⚠️ Could not load .env file: %v", err)
	}

	cfg := &config.Config{
		CaptchaAPIKey:  os.Getenv("CAPTCHA_API_KEY"),
		SendGridAPIKey: os.Getenv("SENDGRID_API_KEY"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		FrontendURL:    os.Getenv("FRONTEND_URL"),
		ApiKey:         os.Getenv("NEXT_API_KEY"),
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

	log.Println("🚀 Starting LOCAL embassy check...")
	monitor.RunBatchCheck(ctx)
	log.Println("Monitor stopped gracefully")
}

// func (m *Monitor) analyzeAppointmentResults(html string) (bool, error) {
// 	// Negative patterns from your bash script
// 	negativePatterns := []string{
// 		"keine Termine",
// 		"leider keine",
// 		"Es sind zur Zeit",
// 		"nicht verfügbar",
// 		"no appointments",
// 		"Unfortunately, there are",
// 		"currently no",
// 		"at this time",
// 		"will be made available",
// 		"freigeschaltet",
// 		"regelmäßigen Abständen",
// 	}

// 	// If CAPTCHA form appears, solution was wrong
// 	if strings.Contains(html, "captchaText") {
// 		// Check if there's an error message about the CAPTCHA
// 		if strings.Contains(strings.ToLower(html), "falsch") || strings.Contains(strings.ToLower(html), "wrong") {
// 			return false, fmt.Errorf("CAPTCHA failed - solution was wrong (explicit error)")
// 		}
// 		return false, fmt.Errorf("CAPTCHA failed - solution was wrong")
// 	}

// 	// Check for negative indicators
// 	for _, pattern := range negativePatterns {
// 		if strings.Contains(strings.ToLower(html), strings.ToLower(pattern)) {
// 			log.Printf("✅ Found negative indicator: '%s'", pattern)
// 			return false, nil // No appointments
// 		}
// 	}

// 	// No negative patterns found - possible appointments!
// 	log.Printf("🚨 No negative indicators found - appointments might be available!")
// 	return true, nil
// }
