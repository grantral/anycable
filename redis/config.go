package redis

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/rueidis"
)

// RedisConfig contains Redis pubsub adapter configuration
type RedisConfig struct {
	// Redis instance URL or master name in case of sentinels usage
	// or list of URLs if cluster usage
	URL string `toml:"url"`
	// List of Redis Sentinel addresses
	Sentinels string `toml:"sentinels"`
	// Redis Sentinel discovery interval (seconds)
	SentinelDiscoveryInterval int `toml:"sentinel_discovery_interval"`
	// Redis keepalive ping interval (seconds)
	KeepalivePingInterval int `toml:"keepalive_ping_interval"`
	// Path to a client certificate for Redis TLS (optional)
	TLSCert string `toml:"tls_cert"`
	// Path to a client key for Redis TLS (optional)
	TLSKey string `toml:"tls_key"`
	// Path to a CA cert file for Redis TLS (optional)
	TLSCACert string `toml:"tls_ca_cert"`
	// Whether to check server's certificate for validity (in case of rediss:// protocol)
	TLSVerify bool `toml:"tls_verify"`
	// Max number of reconnect attempts
	MaxReconnectAttempts int `toml:"max_reconnect_attempts"`
	// Disable client-side caching
	DisableCache bool `toml:"disable_cache"`

	// List of hosts to connect
	hosts []string
	// Sentinel Master host to connect
	sentinelMaster string

	mu sync.RWMutex
}

// NewRedisConfig builds a new config for Redis pubsub
func NewRedisConfig() RedisConfig {
	return RedisConfig{
		KeepalivePingInterval:     30,
		URL:                       "redis://localhost:6379",
		SentinelDiscoveryInterval: 30,
		TLSVerify:                 false,
		MaxReconnectAttempts:      5,
		DisableCache:              false,
	}
}

func (config *RedisConfig) IsCluster() bool {
	config.mu.RLock()
	defer config.mu.RUnlock()

	return len(config.hosts) > 1 && !config.IsSentinel()
}

func (config *RedisConfig) IsSentinel() bool {
	config.mu.RLock()
	defer config.mu.RUnlock()

	return config.Sentinels != "" || config.sentinelMaster != ""
}

func (config *RedisConfig) Hostnames() []string {
	config.mu.RLock()
	defer config.mu.RUnlock()

	return config.hosts
}

func (config *RedisConfig) Hostname() string {
	config.mu.RLock()
	defer config.mu.RUnlock()

	if config.IsSentinel() {
		return config.sentinelMaster
	} else {
		return config.hosts[0]
	}
}

func (config *RedisConfig) ToRueidisOptions() (options *rueidis.ClientOption, err error) {
	if config.IsSentinel() {
		options, err = config.parseSentinels()
	} else {
		options, err = parseRedisURL(config.URL)
	}

	if err != nil {
		return nil, err
	}

	config.mu.Lock()
	config.hosts = append([]string{}, options.InitAddress...)
	config.sentinelMaster = options.Sentinel.MasterSet
	config.mu.Unlock()

	options.Dialer.KeepAlive = time.Duration(config.KeepalivePingInterval) * time.Second

	options.ShuffleInit = config.IsCluster()

	if err := config.configureTLS(options.Sentinel.TLSConfig); err != nil {
		return nil, err
	}

	if err := config.configureTLS(options.TLSConfig); err != nil {
		return nil, err
	}

	options.DisableCache = config.DisableCache

	return options, nil
}

func (config *RedisConfig) configureTLS(tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return nil
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	if config.TLSCert != "" && config.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			return err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.TLSCACert != "" {
		caCert, err := os.ReadFile(config.TLSCACert)
		if err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return errors.New("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	tlsConfig.InsecureSkipVerify = !config.TLSVerify

	return nil
}

func (config *RedisConfig) parseSentinels() (*rueidis.ClientOption, error) {
	config.mu.RLock()
	defer config.mu.RUnlock()

	masterURL, err := url.Parse(config.URL)

	if err != nil {
		return nil, err
	}

	masterOptions, err := parseRedisURL(config.URL)

	if err != nil {
		return nil, err
	}

	sentinelOptions, err := parseRedisURL(config.Sentinels)

	if err != nil {
		return nil, err
	}

	sentinelOptions.Sentinel.TLSConfig = sentinelOptions.TLSConfig
	sentinelOptions.Sentinel.MasterSet = masterURL.Hostname()
	sentinelOptions.Sentinel.Username = sentinelOptions.Username
	sentinelOptions.Sentinel.Password = sentinelOptions.Password

	sentinelOptions.TLSConfig = masterOptions.TLSConfig
	sentinelOptions.Username = masterOptions.Username
	sentinelOptions.Password = masterOptions.Password

	return sentinelOptions, nil
}

func (config *RedisConfig) ToToml() string {
	config.mu.RLock()
	defer config.mu.RUnlock()

	var result strings.Builder

	result.WriteString("# Redis instance URL or master name in case of sentinels usage\n")
	result.WriteString("# or list of URLs if cluster usage\n")
	result.WriteString(fmt.Sprintf("url = \"%s\"\n", config.URL))

	result.WriteString("# Sentinel addresses (comma-separated list)\n")
	result.WriteString(fmt.Sprintf("sentinels = \"%s\"\n", config.Sentinels))

	result.WriteString("# Sentinel discovery interval (seconds)\n")
	result.WriteString(fmt.Sprintf("sentinel_discovery_interval = %d\n", config.SentinelDiscoveryInterval))

	result.WriteString("# Keepalive ping interval (seconds)\n")
	result.WriteString(fmt.Sprintf("keepalive_ping_interval = %d\n", config.KeepalivePingInterval))

	result.WriteString("# Enable TLS Verify\n")
	if config.TLSVerify {
		result.WriteString(fmt.Sprintf("tls_verify = %t\n", config.TLSVerify))
	} else {
		result.WriteString("# tls_verify = true\n")
	}

	result.WriteString("# Max number of reconnect attempts\n")
	result.WriteString(fmt.Sprintf("max_reconnect_attempts = %d\n", config.MaxReconnectAttempts))

	result.WriteString("# Disable client-side caching\n")
	if config.DisableCache {
		result.WriteString(fmt.Sprintf("disable_cache = %t\n", config.DisableCache))
	} else {
		result.WriteString("# disable_cache = true\n")
	}

	result.WriteString("\n")

	return result.String()
}

func parseRedisURL(url string) (options *rueidis.ClientOption, err error) {
	urls := strings.Split(url, ",")

	for _, addr := range urls {
		addr = chompTrailingSlashHostname(addr)

		currentOptions, err := rueidis.ParseURL(ensureRedisScheme(addr))

		if err != nil {
			return nil, err
		}

		if options == nil {
			options = &currentOptions
		} else {
			options.InitAddress = append(options.InitAddress, currentOptions.InitAddress...)
		}
	}

	return options, nil
}

// TODO: upstream this change to `rueidis` URL parsing
// as the implementation doesn't tolerate the trailing slash hostnames (`redis-cli` does).
func chompTrailingSlashHostname(url string) string {
	return strings.TrimSuffix(url, "/")
}

func ensureRedisScheme(url string) string {
	if strings.Contains(url, "://") {
		return url
	}

	return "redis://" + url
}
