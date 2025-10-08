package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Subscriber struct {
	Email     string `json:"email"`
	Location  string `json:"location,omitempty"`
	Tier      string `json:"tier,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
}

type Database struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

type SubscribersResponse struct {
	Success     bool         `json:"success"`
	Subscribers []Subscriber `json:"subscribers"`
	Count       int          `json:"count"`
	Error       string       `json:"error,omitempty"`
}

func NewDatabase(baseURL, apiKey string) *Database {
	return &Database{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{},
	}
}

// GetSubscribersByLocationAndTier returns just email strings (for easy use in alerts)
func (db *Database) GetSubscribersByLocationAndTier(location, tier string) ([]string, error) {
	subscribers, err := db.GetSubscribersWithFilters(location, tier)
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
		return nil, fmt.Errorf("no valid email addresses found for location=%s, tier=%s", location, tier)
	}

	return emails, nil
}

// GetSubscribersWithFilters returns full Subscriber objects
func (db *Database) GetSubscribersWithFilters(location, tier string) ([]Subscriber, error) {
	if db.baseURL == "" {
		return nil, fmt.Errorf("database URL not configured")
	}

	// Build URL with query parameters
	apiURL := fmt.Sprintf("%s/api/admin/subscribers", db.baseURL)

	// Add query parameters if provided
	var queryParams url.Values
	if location != "" || tier != "" {
		queryParams = url.Values{}
		if location != "" {
			queryParams.Add("location", location)
		}
		if tier != "" {
			queryParams.Add("tier", tier)
		}
		apiURL = apiURL + "?" + queryParams.Encode()
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add API key header
	if db.apiKey != "" {
		req.Header.Set("x-api-key", db.apiKey)
	}

	fmt.Println("API KEY: ", db.apiKey)
	fmt.Println("Request: ", req)

	req.Header.Set("User-Agent", "VisaMonitor/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := db.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Handle unauthorized response
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("API authentication failed: invalid API key")
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

	fmt.Printf("✅ Found %d subscribers for location=%s, tier=%s\n",
		result.Count, location, tier)
	return result.Subscribers, nil
}

// GetSubscribers returns all subscribers (full objects)
func (db *Database) GetSubscribers() ([]Subscriber, error) {
	return db.GetSubscribersWithFilters("", "")
}

// GetSubscriberEmails returns just email strings (backward compatibility)
func (db *Database) GetSubscriberEmails() ([]string, error) {
	return db.GetSubscribersByLocationAndTier("", "")
}

// HealthCheck verifies the database connection
func (db *Database) HealthCheck() error {
	if db.baseURL == "" {
		return fmt.Errorf("database URL not configured")
	}

	// Try the subscribers endpoint for health check
	_, err := db.GetSubscribers()
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	fmt.Println("✅ Database connection healthy")
	return nil
}
