package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Subscriber struct {
	Email     string `json:"email"`
	CreatedAt string `json:"createdAt,omitempty"`
}

type Database struct {
	baseURL string
	client  *http.Client
}

type SubscribersResponse struct {
	Success     bool         `json:"success"`
	Subscribers []Subscriber `json:"subscribers"`
	Count       int          `json:"count"`
	Error       string       `json:"error,omitempty"`
}

func NewDatabase(baseURL string) *Database {
	return &Database{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

// GetSubscribers fetches all subscribers from your API
func (db *Database) GetSubscribers() ([]Subscriber, error) {
	if db.baseURL == "" {
		return nil, fmt.Errorf("database URL not configured")
	}

	// Make request to your Vercel API endpoint (matches your bash script)
	url := fmt.Sprintf("%s/api/admin/subscribers", db.baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "VisaMonitor/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := db.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status: %d %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}

	var result SubscribersResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode JSON response: %w, body: %s", err, string(body))
	}

	if !result.Success {
		if result.Error != "" {
			return nil, fmt.Errorf("API error: %s", result.Error)
		}
		return nil, fmt.Errorf("API request unsuccessful")
	}

	fmt.Printf("✅ Found %d subscribers in database\n", result.Count)
	return result.Subscribers, nil
}

// GetSubscriberEmails returns just the email addresses (used by monitor)
func (db *Database) GetSubscriberEmails() ([]string, error) {
	subscribers, err := db.GetSubscribers()
	if err != nil {
		return nil, err
	}

	emails := make([]string, 0, len(subscribers))
	for _, sub := range subscribers {
		if sub.Email != "" && strings.Contains(sub.Email, "@") {
			emails = append(emails, sub.Email)
		}
	}

	if len(emails) == 0 {
		return nil, fmt.Errorf("no valid email addresses found in subscribers")
	}

	return emails, nil
}

// AddSubscriber adds a new subscriber (for future use)
func (db *Database) AddSubscriber(email string) error {
	if db.baseURL == "" {
		return fmt.Errorf("database URL not configured")
	}

	payload := map[string]string{
		"email": email,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/subscribers", db.baseURL)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VisaMonitor/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := db.client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status: %d %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}

	fmt.Printf("✅ Subscriber added: %s\n", email)
	return nil
}

// HealthCheck verifies the database connection
func (db *Database) HealthCheck() error {
	if db.baseURL == "" {
		return fmt.Errorf("database URL not configured")
	}

	// Try a more common endpoint, or remove health check temporarily
	req, err := http.NewRequest("GET", db.baseURL+"/api/health", nil)
	if err != nil {
		fmt.Println(db.baseURL + "/api/health")
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := db.client.Do(req)
	if err != nil {
		fmt.Println(db.baseURL + "/api/health")
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	// Accept any 2xx status as healthy, or remove this check entirely
	if resp.StatusCode >= 400 {
		return fmt.Errorf("health check failed: status %d %s", resp.StatusCode, resp.Status)
	}

	fmt.Println("✅ Database connection healthy")
	return nil
}
