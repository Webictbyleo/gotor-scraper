package torscraper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Job represents a single scrape task to be processed by the worker pool.
type Job struct {
	ID         string
	URL        string
	Method     string
	Headers    map[string]string
	Payload    any
	Meta       any // Arbitrary user metadata passed along with the job
	RenderJS   bool
	RenderOpts []RenderOption
}

// Result represents the outcome of a processed Job.
type Result struct {
	Job        Job
	Response   *Response
	Error      error
	Duration   time.Duration
	RetryCount int
}

// PoolConfig configures the WorkerPool.
type PoolConfig struct {
	// Workers is the maximum number of concurrent scraping goroutines.
	Workers int

	// RateLimit is an optional rate limit per second (e.g. 5.0 for 5 req/s). Set 0 to disable.
	RateLimit float64

	// MaxRetries is the number of retry attempts for failed requests.
	MaxRetries int

	// RetryBackoff is the initial backoff duration between retries (doubles each attempt).
	RetryBackoff time.Duration

	// RotateTorOnRetry causes retried requests to use an isolated Tor circuit.
	RotateTorOnRetry bool
}

// EnsureDefaults sets sensible fallback defaults for PoolConfig.
func (c *PoolConfig) EnsureDefaults() {
	if c.Workers <= 0 {
		c.Workers = 5
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 1 * time.Second
	}
}

// WorkerPool manages concurrent scraping jobs using a pool of goroutines.
type WorkerPool struct {
	client  *Client
	config  PoolConfig
	limiter *rate.Limiter
}

// NewWorkerPool creates a new WorkerPool using the provided Client and PoolConfig.
func NewWorkerPool(client *Client, config PoolConfig) *WorkerPool {
	config.EnsureDefaults()

	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), int(config.RateLimit+1))
	}

	return &WorkerPool{
		client:  client,
		config:  config,
		limiter: limiter,
	}
}

// ScrapeBatch submits a slice of URLs, processes them concurrently, and returns all results.
func (p *WorkerPool) ScrapeBatch(ctx context.Context, urls []string) []*Result {
	jobs := make([]Job, len(urls))
	for i, u := range urls {
		jobs[i] = Job{
			ID:     fmt.Sprintf("job_%d", i+1),
			URL:    u,
			Method: http.MethodGet,
		}
	}
	return p.Process(ctx, jobs)
}

// ScrapeBatchRender submits a slice of URLs to be rendered concurrently with headless Chrome.
// It leverages the Client's shared browser instance, running jobs in parallel browser tabs
// without the overhead of spawning a new browser process for each URL.
func (p *WorkerPool) ScrapeBatchRender(ctx context.Context, urls []string, renderOpts ...RenderOption) []*Result {
	jobs := make([]Job, len(urls))
	for i, u := range urls {
		jobs[i] = Job{
			ID:         fmt.Sprintf("render_job_%d", i+1),
			URL:        u,
			Method:     http.MethodGet,
			RenderJS:   true,
			RenderOpts: renderOpts,
		}
	}
	return p.Process(ctx, jobs)
}

// Process executes a batch of Jobs concurrently across the worker pool.
func (p *WorkerPool) Process(ctx context.Context, jobs []Job) []*Result {
	jobChan := make(chan Job, len(jobs))
	resultChan := make(chan *Result, len(jobs))

	for _, j := range jobs {
		jobChan <- j
	}
	close(jobChan)

	var wg sync.WaitGroup
	numWorkers := p.config.Workers
	if len(jobs) < numWorkers {
		numWorkers = len(jobs)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobChan {
				if ctx.Err() != nil {
					resultChan <- &Result{
						Job:   job,
						Error: ctx.Err(),
					}
					continue
				}
				res := p.executeJob(ctx, job)
				resultChan <- res
			}
		}(i)
	}

	wg.Wait()
	close(resultChan)

	results := make([]*Result, 0, len(jobs))
	for res := range resultChan {
		results = append(results, res)
	}
	return results
}

// executeJob runs a single job with rate limiting, optional headless Chrome rendering, and exponential backoff retry.
func (p *WorkerPool) executeJob(ctx context.Context, job Job) *Result {
	var resp *Response
	var err error
	var duration time.Duration

	retries := 0
	backoff := p.config.RetryBackoff

	for {
		// Wait for rate limiter if configured
		if p.limiter != nil {
			if waitErr := p.limiter.Wait(ctx); waitErr != nil {
				return &Result{
					Job:   job,
					Error: waitErr,
				}
			}
		}

		start := time.Now()

		if job.RenderJS {
			// Execute through headless Chrome CDP (reusing shared browser process tab)
			resp, err = p.client.GetRendered(ctx, job.URL, job.RenderOpts...)
		} else {
			// Execute through standard uTLS HTTP/HTTP2 transport.
			// Disable inner client retries so WorkerPool controls retry count exclusively.
			reqOpts := []RequestOption{ReqWithRetries(0)}
			if len(job.Headers) > 0 {
				reqOpts = append(reqOpts, ReqWithHeaders(job.Headers))
			}

			// If Tor rotation on retry is requested and we are on a retry
			if retries > 0 && p.config.RotateTorOnRetry && p.client.cfg.torConfig != nil && p.client.cfg.torConfig.Enabled {
				reqOpts = append(reqOpts, ReqWithTor(&TorConfig{
					Enabled:         true,
					ProxyAddr:       p.client.cfg.torConfig.ProxyAddr,
					StreamIsolation: true, // Forces new circuit
				}))
			}

			method := job.Method
			if method == "" {
				method = http.MethodGet
			}

			if method == http.MethodGet && job.Payload == nil {
				resp, err = p.client.Get(ctx, job.URL, reqOpts...)
			} else if method == http.MethodPost && job.Payload != nil {
				resp, err = p.client.PostJSON(ctx, job.URL, job.Payload, reqOpts...)
			} else {
				var bodyReader io.Reader
				isJSONPayload := false
				if job.Payload != nil {
					switch v := job.Payload.(type) {
					case io.Reader:
						bodyReader = v
					case []byte:
						bodyReader = bytes.NewReader(v)
					case string:
						bodyReader = strings.NewReader(v)
					default:
						data, mErr := json.Marshal(job.Payload)
						if mErr != nil {
							err = fmt.Errorf("failed to marshal job payload: %w", mErr)
						} else {
							bodyReader = bytes.NewReader(data)
							isJSONPayload = true
						}
					}
				}
				if err == nil {
					req, rErr := http.NewRequestWithContext(ctx, method, job.URL, bodyReader)
					if rErr != nil {
						err = rErr
					} else {
						if isJSONPayload && req.Header.Get("Content-Type") == "" {
							req.Header.Set("Content-Type", "application/json")
						}
						resp, err = p.client.Do(req, reqOpts...)
					}
				}
			}
		}
		duration = time.Since(start)

		// Check if we should retry
		shouldRetry := false
		if retries < p.config.MaxRetries {
			if p.client.cfg.retryCondition != nil {
				shouldRetry = p.client.cfg.retryCondition(resp, err)
			} else {
				if err != nil &&
					!errors.Is(err, ErrContentLengthExceeded) &&
					!errors.Is(err, ErrContentTypeBlocked) &&
					!errors.Is(err, ErrContentTypeNotAllowed) &&
					!errors.Is(err, ErrContentRejected) &&
					!errors.Is(err, ErrAntiBotBlocked) {
					var blockedErr *BlockedError
					if !errors.As(err, &blockedErr) {
						shouldRetry = true
					}
				} else if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) {
					shouldRetry = true
				}
			}
		}

		if shouldRetry {
			retries++

			// Trigger OnRetry lifecycle hook if configured
			if p.client.cfg.hooks != nil && p.client.cfg.hooks.OnRetry != nil {
				retryReq, _ := http.NewRequestWithContext(ctx, job.Method, job.URL, nil)
				p.client.cfg.hooks.OnRetry(retryReq, err, retries, backoff)
			}

			select {
			case <-ctx.Done():
				return &Result{
					Job:        job,
					Error:      ctx.Err(),
					RetryCount: retries,
				}
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
				continue
			}
		}

		break
	}

	return &Result{
		Job:        job,
		Response:   resp,
		Error:      err,
		Duration:   duration,
		RetryCount: retries,
	}
}
