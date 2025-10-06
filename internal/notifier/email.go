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
		from:   "noreply@embassyalerts.com", // From your bash script
	}
}

func (n *EmailNotifier) SendAppointmentAlert(to, embassyName, frontendURL string) error {
	// Clean subject without emojis or spammy language
	subject := fmt.Sprintf("German Embassy Visa Appointments Available - %s", embassyName)

	// Plain text version
	plainBody := fmt.Sprintf(`German Embassy Visa Appointment Alert

Appointments may be available at the German Embassy in %s for National Visas.

Check the official website:
https://service2.diplo.de/rktermin

Time detected: %s

This is an automated alert. Please verify availability on the official website.

To manage your notifications or unsubscribe, visit:
%s

--
German Embassy Appointment Finder
noreply@embassyalerts.com`, embassyName, getCurrentTime(), frontendURL)

	// HTML version (better deliverability)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
    <div style="background: linear-gradient(to right, #000000, #DD0000, #FFCE00); height: 4px;"></div>
    
    <div style="padding: 20px;">
        <h2 style="color: #2c3e50; margin-bottom: 10px;">German Embassy Visa Appointment Alert</h2>
        
        <p>Appointments may be available at the German Embassy in <strong>%s</strong> for National Visas.</p>
        
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #DD0000; margin: 20px 0;">
            <p style="margin: 0;"><strong>Check availability now:</strong></p>
            <p style="margin: 10px 0 0 0;">
                <a href="https://service2.diplo.de/rktermin" 
                   style="color: #DD0000; text-decoration: none; font-weight: bold;">
                   Official Embassy Website →
                </a>
            </p>
        </div>
        
        <p><small>Time detected: %s</small></p>
        
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 25px 0;">
        
        <div style="font-size: 12px; color: #666;">
            <p>This is an automated alert from the German Embassy Appointment Finder service.</p>
            <p>
                <a href="%s" style="color: #666; text-decoration: underline;">
                    Manage your notification preferences
                </a>
            </p>
        </div>
        
        <div style="font-size: 11px; color: #999; margin-top: 20px; padding-top: 15px; border-top: 1px solid #f0f0f0;">
            <p>German Embassy Appointment Finder<br>
            contact@embassyalerts.com</p>
        </div>
    </div>
</body>
</html>`, embassyName, getCurrentTime(), frontendURL)

	return n.SendWithHTML(to, subject, plainBody, htmlBody)
}

// SendWithHTML sends email with both plain text and HTML versions
func (n *EmailNotifier) SendWithHTML(to, subject, plainText, html string) error {
	if n.apiKey == "" {
		return fmt.Errorf("SendGrid API key not configured")
	}

	// Prepare SendGrid API request with improved headers
	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": to},
				},
				"headers": map[string]string{
					"List-Unsubscribe":      fmt.Sprintf("<%s>", "https://embassyalerts.com/unsubscribe"),
					"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
					"X-Entity-Ref":          "embassy-alerts-1.0",
				},
			},
		},
		"from": map[string]string{
			"email": n.from,
			"name":  "Embassy Alerts", // Friendly sender name
		},
		"reply_to": map[string]string{
			"email": "contact@embassyalerts.com",
			"name":  "Embassy Alerts Support",
		},
		"subject": subject,
		"content": []map[string]string{
			{
				"type":  "text/plain",
				"value": plainText,
			},
			{
				"type":  "text/html",
				"value": html,
			},
		},
		"mail_settings": map[string]interface{}{
			"bypass_list_management": map[string]bool{
				"enable": false,
			},
			"spam_check": map[string]bool{
				"enable": false,
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
	req.Header.Set("User-Agent", "EmbassyAlerts/1.0")

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

	fmt.Printf("✅ Email sent successfully to: %s\n", to)
	return nil
}

// Send is kept for backward compatibility
func (n *EmailNotifier) Send(email Email) error {
	return n.SendWithHTML(email.To, email.Subject, email.Body, "")
}

// Helper function to get current time string
func getCurrentTime() string {
	return time.Now().Format("January 2, 2006 at 15:04 MST")
}
