package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/oluwasemilore/aegis/internal/pkg/apierror"
)

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func newTokenBucket(ratePerMin int) *tokenBucket {
	max := float64(ratePerMin)
	return &tokenBucket{
		tokens:     max,
		maxTokens:  max,
		refillRate: max / 60.0,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RateLimiter holds per-tenant rate limiters.
type RateLimiter struct {
	buckets map[string]*tokenBucket
	mu      sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with cleanup.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{buckets: make(map[string]*tokenBucket)}
	// Cleanup stale buckets every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-30 * time.Minute)
	for key, bucket := range rl.buckets {
		bucket.mu.Lock()
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, key)
		}
		bucket.mu.Unlock()
	}
}

func (rl *RateLimiter) getBucket(tenantID string, ratePerMin int) *tokenBucket {
	rl.mu.RLock()
	bucket, ok := rl.buckets[tenantID]
	rl.mu.RUnlock()
	if ok {
		return bucket
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	// Double-check after acquiring write lock
	if bucket, ok = rl.buckets[tenantID]; ok {
		return bucket
	}
	bucket = newTokenBucket(ratePerMin)
	rl.buckets[tenantID] = bucket
	return bucket
}

// Middleware returns the rate limiting middleware.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := TenantFromContext(r.Context())
			if tenant == nil {
				next.ServeHTTP(w, r)
				return
			}

			bucket := rl.getBucket(tenant.ID.String(), tenant.RateLimitPerMin)
			if !bucket.allow() {
				reqID := r.Header.Get("X-Request-ID")
				w.Header().Set("Retry-After", "1")
				apierror.WriteError(w, reqID, apierror.RateLimited())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
