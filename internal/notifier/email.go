package notifier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type EmailNotifier struct {
	apiKey string
	client *http.Client
	from   string
}

type Email struct {
	To      string
	Subject string
	Body    string
}

type SendGridResponse struct {
	Errors []SendGridError `json:"errors"`
}

type SendGridError struct {
	Message string `json:"message"`
	Field   string `json:"field"`
	Help    string `json:"help"`
}

func NewEmailNotifier(apiKey string) *EmailNotifier {
	return &EmailNotifier{
		apiKey: apiKey,
		client: &http.Client{},
		from:   "hunterjohnst1@gmail.com", // From your bash script
	}
}

// Send sends an email using SendGrid API
func (n *EmailNotifier) Send(email Email) error {
	if n.apiKey == "" {
		return fmt.Errorf("SendGrid API key not configured")
	}

	// Prepare SendGrid API request
	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": email.To},
				},
			},
		},
		"from": map[string]string{
			"email": n.from,
		},
		"subject": email.Subject,
		"content": []map[string]string{
			{
				"type":  "text/plain",
				"value": email.Body,
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send",
		strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+n.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VisaMonitor/1.0")

	// Send request
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("SendGrid API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		var sgResp SendGridResponse
		if err := json.NewDecoder(resp.Body).Decode(&sgResp); err == nil && len(sgResp.Errors) > 0 {
			return fmt.Errorf("SendGrid API error: %s (status: %d)",
				sgResp.Errors[0].Message, resp.StatusCode)
		}
		return fmt.Errorf("SendGrid API returned status: %d", resp.StatusCode)
	}

	fmt.Printf("✅ Email sent successfully to: %s\n", email.To)
	return nil
}

// SendAppointmentAlert sends the visa appointment alert email
func (n *EmailNotifier) SendAppointmentAlert(to, embassyName, frontendURL string) error {
	subject := fmt.Sprintf("🚨 German Embassy Visa Appointments Possibly Available in %s!", embassyName)

	body := fmt.Sprintf(`URGENT: German Embassy Visa Appointment Alert!

Our system detected that appointments MAY be available at the German Embassy in %s for National Visas.

Check immediately:
https://service2.diplo.de/rktermin

Time detected: %s

Note: This is an automated alert. Please verify availability on the official website.

To unsubscribe, visit: %s

--
German Embassy Appointment Finder`, embassyName, getCurrentTime(), frontendURL)

	email := Email{
		To:      to,
		Subject: subject,
		Body:    body,
	}

	return n.Send(email)
}

// Helper function to get current time string
func getCurrentTime() string {
	// You can format this however you like
	return time.Now().Format("2006-01-02 15:04:05")
}
