package proxy

import (
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	proxyURLs []string
	rng       *rand.Rand
	mu        sync.RWMutex
	loaded    bool = false
)

func init() {
	// Initialize random generator only
	rng = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func ensureLoaded() {
	if !loaded {
		loadProxiesFromEnv()
		loaded = true
	}
}

func loadProxiesFromEnv() {
	mu.Lock()
	defer mu.Unlock()

	proxyURLs = []string{} // Reset

	proxies := os.Getenv("PROXY_URLS")
	log.Printf("🔍 DEBUG: PROXY_URLS env var value: '%s'", proxies) // Debug line

	if proxies == "" {
		log.Printf("⚠️ No PROXY_URLS environment variable found - will use direct connections")
		return
	}

	proxyList := strings.Split(proxies, ",")
	for i, p := range proxyList {
		proxy := strings.TrimSpace(p)
		if proxy != "" {
			proxyURLs = append(proxyURLs, proxy)
			log.Printf("✅ Loaded proxy %d: %s", i+1, maskProxyURL(proxy))
		}
	}

	log.Printf("🎯 Loaded %d proxies from environment", len(proxyURLs))
}

func maskProxyURL(proxy string) string {
	if strings.Contains(proxy, "@") {
		parts := strings.Split(proxy, "@")
		if len(parts) == 2 {
			return "***@" + parts[1]
		}
	}
	return proxy
}

func GetRandomProxy() string {
	ensureLoaded() // Load on first use
	mu.RLock()
	defer mu.RUnlock()

	if len(proxyURLs) == 0 {
		return ""
	}
	return proxyURLs[rng.Intn(len(proxyURLs))]
}

// NewProxiedClient creates an HTTP client with a random proxy
func NewProxiedClient() *http.Client {
	ensureLoaded() // Load on first use
	proxyStr := GetRandomProxy()
	if proxyStr == "" {
		log.Printf("🔗 No proxies available, using direct connection")
		return &http.Client{Timeout: 30 * time.Second}
	}

	log.Printf("🔄 Using proxy: %s", maskProxyURL(proxyStr))
	return newProxiedClient(proxyStr)
}

// NewProxiedClientWithProxy creates an HTTP client with specific proxy
func NewProxiedClientWithProxy(proxyStr string) *http.Client {
	if proxyStr == "" {
		return &http.Client{Timeout: 30 * time.Second}
	}

	log.Printf("🔄 Using specified proxy: %s", maskProxyURL(proxyStr))
	return newProxiedClient(proxyStr)
}

func newProxiedClient(proxyStr string) *http.Client {
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Printf("❌ Failed to parse proxy URL %s: %v", maskProxyURL(proxyStr), err)
		return &http.Client{Timeout: 30 * time.Second}
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// GetProxyCount returns the number of available proxies
func GetProxyCount() int {
	ensureLoaded() // Load on first use
	mu.RLock()
	defer mu.RUnlock()
	return len(proxyURLs)
}
