package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/limit"
)

type Factory struct {
	mu            sync.Mutex
	clients       map[string]*Client
	retries       int
	globalLimiter *limit.Limiter
	logger        *slog.Logger
}

type Client struct {
	source        config.EffectiveSource
	client        *http.Client
	sourceLimiter *limit.Limiter
	globalLimiter *limit.Limiter
	retries       int
	logger        *slog.Logger
}

// StatusError reports a non-successful HTTP response. Callers may use IsStatus
// to distinguish an explicitly missing resource from transport and server
// failures without parsing the error text.
type StatusError struct {
	RepoName   string
	SourceHost string
	Path       string
	Status     string
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s request source %s file %s returned %s", e.RepoName, e.SourceHost, e.Path, e.Status)
}

func IsStatus(err error, statusCode int) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

var retryBackoff = func(attempt int) time.Duration {
	return time.Duration(attempt) * time.Second
}

func NewFactory(retries int, globalLimiter *limit.Limiter, loggers ...*slog.Logger) *Factory {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &Factory{clients: map[string]*Client{}, retries: retries, globalLimiter: globalLimiter, logger: logger}
}

func (f *Factory) Client(src config.EffectiveSource) (*Client, error) {
	key := fmt.Sprintf("%s|%s|%t|%d|%d", src.URL, src.ProxyURL, src.DirectProxy, src.MaxConnections, src.MaxInFlightRequests)
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.clients[key]; c != nil {
		return c, nil
	}
	tr, err := transport(src)
	if err != nil {
		return nil, err
	}
	c := &Client{
		source: src,
		client: &http.Client{
			Transport: tr,
			Timeout:   0,
		},
		sourceLimiter: limit.New(src.MaxInFlightRequests),
		globalLimiter: f.globalLimiter,
		retries:       f.retries,
		logger:        f.logger,
	}
	f.clients[key] = c
	return c, nil
}

func transport(src config.EffectiveSource) (*http.Transport, error) {
	var proxy func(*http.Request) (*url.URL, error)
	if !src.DirectProxy && src.ProxyURL != "" {
		u, err := url.Parse(src.ProxyURL)
		if err != nil {
			return nil, err
		}
		proxy = http.ProxyURL(u)
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 proxy,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       src.MaxConnections,
		MaxIdleConns:          src.MaxConnections * 4,
		MaxIdleConnsPerHost:   src.MaxConnections,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}, nil
}

func (c *Client) URL(rel string) string {
	return c.source.URL + "/" + strings.TrimLeft(rel, "/")
}

func (c *Client) Host() string {
	u, err := url.Parse(c.source.URL)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

func (c *Client) ProxyHost() string {
	if c.source.DirectProxy || c.source.ProxyURL == "" {
		return "direct"
	}
	u, err := url.Parse(c.source.ProxyURL)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

func (c *Client) GetBytes(ctx context.Context, rel string, maxBytes int64) ([]byte, error) {
	var out []byte
	err := c.Do(ctx, rel, func(resp *http.Response) error {
		reader := resp.Body
		if maxBytes > 0 {
			reader = http.MaxBytesReader(nil, resp.Body, maxBytes)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		out = data
		return nil
	})
	return out, err
}

func (c *Client) Do(ctx context.Context, rel string, consume func(*http.Response) error) error {
	url := c.URL(rel)
	var last error
	for attempt := 0; attempt <= c.retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		releaseSource, err := c.sourceLimiter.Acquire(ctx)
		if err != nil {
			return err
		}
		releaseGlobal, err := c.globalLimiter.Acquire(ctx)
		if err != nil {
			releaseSource()
			return err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			releaseGlobal()
			releaseSource()
			last = fmt.Errorf("%s request source %s file %s via %s failed: %w", c.source.RepoName, c.Host(), strings.TrimLeft(rel, "/"), c.ProxyHost(), transportCause(err))
		} else {
			err = func() error {
				defer releaseSource()
				defer releaseGlobal()
				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					io.Copy(io.Discard, resp.Body)
					return &StatusError{
						RepoName: c.source.RepoName, SourceHost: c.Host(), Path: strings.TrimLeft(rel, "/"),
						Status: resp.Status, StatusCode: resp.StatusCode,
					}
				}
				return consume(resp)
			}()
			if err == nil {
				return nil
			}
			last = err
		}
		if attempt < c.retries {
			if !retryableHTTPError(last) {
				return last
			}
			delay := retryBackoff(attempt + 1)
			c.logger.Warn("HTTP request failed; retrying",
				"repository", c.source.RepoName,
				"source_host", c.Host(),
				"path", strings.TrimLeft(rel, "/"),
				"proxy_host", c.ProxyHost(),
				"attempt", attempt+1,
				"next_attempt", attempt+2,
				"delay", delay,
				"error", last,
			)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return last
}

func retryableHTTPError(err error) bool {
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		return true
	}
	if statusErr.StatusCode >= 500 {
		return true
	}
	switch statusErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func transportCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func (c *Client) ProxyMode() string {
	if c.source.DirectProxy || c.source.ProxyURL == "" {
		return "direct"
	}
	return c.source.ProxyURL
}

func (c *Client) Source() config.EffectiveSource {
	return c.source
}
