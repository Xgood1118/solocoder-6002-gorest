package service

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mediocregopher/radix/v4"
	log "github.com/sirupsen/logrus"

	"github.com/pilinux/gorest/config"
	"github.com/pilinux/gorest/database"
	"github.com/pilinux/gorest/database/model"
)

// --- Account lockout ---

// useRedisForLockout reports whether Redis should be used for lockout state.
// When Redis is not enabled/available the caller should fall back to the
// in-memory store.
func useRedisForLockout() bool {
	return config.IsRedis()
}

// IsAccountLocked reports whether the given authID is currently locked out.
// On success it returns locked=true plus the time the lock expires (zero time
// if not locked). A non-nil error means the backend (Redis or memory) could
// not be queried; callers are expected to treat such failures as "not locked"
// to avoid Redis outages taking down the login path.
func IsAccountLocked(authID uint64) (locked bool, lockUntil time.Time, err error) {
	if authID == 0 {
		return false, time.Time{}, nil
	}

	if useRedisForLockout() {
		client := database.GetRedis()
		if client != nil {
			rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
			defer cancel()

			lockKey := model.AccountLockKeyPrefix + strconv.FormatUint(authID, 10)
			exists := 0
			if rErr := client.Do(ctx, radix.FlatCmd(&exists, "EXISTS", lockKey)); rErr == nil && exists > 0 {
				// locked: try to read TTL for informational purposes
				ttlSec := -2
				_ = client.Do(ctx, radix.FlatCmd(&ttlSec, "TTL", lockKey))
				until := time.Time{}
				if ttlSec > 0 {
					until = time.Now().Add(time.Duration(ttlSec) * time.Second)
				}
				return true, until, nil
			} else if rErr != nil {
				log.WithError(rErr).WithField("authID", authID).Warn("lockout: Redis EXISTS failed, falling back to in-memory")
				// fall through to in-memory fallback
			} else {
				return false, time.Time{}, nil
			}
		}
	}

	// in-memory fallback
	attempts, lockUntilMem, ok := model.InMemoryLockout.Get(authID)
	_ = attempts
	if ok && !lockUntilMem.IsZero() && lockUntilMem.After(time.Now()) {
		return true, lockUntilMem, nil
	}
	return false, time.Time{}, nil
}

// RecordFailedLogin increments the failed-login counter for authID.
// It returns the new attempt count and whether the account has just become
// locked as a result of this call.
//
// Redis is preferred; on failure the in-memory store is used. Errors are
// logged but never returned to the caller so that a Redis outage never
// breaks the login flow.
func RecordFailedLogin(authID uint64) (attempts int, lockedNow bool) {
	if authID == 0 {
		return 0, false
	}

	lockDuration := time.Duration(model.AccountLockDurationMinutes) * time.Minute
	maxAttempts := model.MaxLoginAttempts

	if useRedisForLockout() {
		client := database.GetRedis()
		if client != nil {
			rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
			defer cancel()

			attemptKey := model.LoginAttemptKeyPrefix + strconv.FormatUint(authID, 10)
			lockKey := model.AccountLockKeyPrefix + strconv.FormatUint(authID, 10)

			// INCR attempts
			newCount := 0
			if err := client.Do(ctx, radix.FlatCmd(&newCount, "INCR", attemptKey)); err != nil {
				log.WithError(err).WithField("authID", authID).Warn("lockout: Redis INCR failed, falling back to in-memory")
				goto MemoryFallback
			}
			attempts = newCount

			// set/refresh TTL on the attempts key
			ttlSec := int(lockDuration.Seconds())
			_ = client.Do(ctx, radix.FlatCmd(nil, "EXPIRE", attemptKey, ttlSec))

			if attempts >= maxAttempts {
				// lock the account
				ok := ""
				if err := client.Do(ctx, radix.FlatCmd(&ok, "SET", lockKey, "1", "EX", ttlSec, "NX")); err == nil {
					lockedNow = true
				}
				// if NX returned nil because the key already existed, we still
				// report the account is not *newly* locked on this call
			}
			return attempts, lockedNow
		}
	}

MemoryFallback:
	attempts = model.InMemoryLockout.Increment(authID)
	if attempts >= maxAttempts {
		until := time.Now().Add(lockDuration)
		model.InMemoryLockout.SetLock(authID, until)
		lockedNow = true
	}
	return attempts, lockedNow
}

// ResetLoginAttempts clears the failed-login counter and any active lock for
// authID. It is called after a successful authentication.
func ResetLoginAttempts(authID uint64) {
	if authID == 0 {
		return
	}

	if useRedisForLockout() {
		client := database.GetRedis()
		if client != nil {
			rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
			defer cancel()

			attemptKey := model.LoginAttemptKeyPrefix + strconv.FormatUint(authID, 10)
			lockKey := model.AccountLockKeyPrefix + strconv.FormatUint(authID, 10)
			// DEL both keys; errors are non-fatal
			_ = client.Do(ctx, radix.FlatCmd(nil, "DEL", attemptKey, lockKey))
		}
	}

	model.InMemoryLockout.Reset(authID)
}

// --- Refresh-token rotation ---

// RotationResult reports the outcome of a refresh-token rotation attempt.
type RotationResult struct {
	// Rotated is true when the old refresh JTI was successfully blacklisted.
	Rotated bool
	// Degraded is true when Redis was unavailable and rotation was skipped.
	// When Degraded is true the caller should surface a warning header to
	// the client so operators know rotation is not being enforced.
	Degraded bool
	// DegradedReason is a short human-readable description of why rotation
	// could not be enforced (for logging / warning headers).
	DegradedReason string
}

// RotateRefreshToken invalidates the supplied refresh JTI by recording it in
// the Redis blacklist with a TTL equal to the token's remaining lifetime.
//
// If Redis is not available (not configured, connection errors, etc.) the
// function returns Degraded=true instead of failing. This keeps the refresh
// flow alive during Redis outages at the cost of temporarily disabling
// rotation enforcement.
func RotateRefreshToken(jtiRefresh string, expRefresh int64) RotationResult {
	res := RotationResult{}

	if jtiRefresh == "" {
		res.Degraded = true
		res.DegradedReason = "missing jti"
		return res
	}

	// Rotation needs JWT invalidation feature + Redis.
	if !config.IsJWT() || !config.InvalidateJWT() || !config.IsRedis() {
		res.Degraded = true
		res.DegradedReason = "rotation disabled by config"
		return res
	}

	client := database.GetRedis()
	if client == nil {
		res.Degraded = true
		res.DegradedReason = "redis client nil"
		return res
	}

	rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
	defer cancel()

	// TTL: remaining lifetime of the refresh token (seconds).
	// If expRefresh is in the past we still use a small positive value so
	// the blacklist record is created but quickly expires.
	remaining := expRefresh - time.Now().Unix()
	if remaining < 1 {
		remaining = 1
	}

	key := config.PrefixJtiBlacklist + jtiRefresh
	value := strconv.FormatInt(expRefresh, 10)

	if err := client.Do(ctx, radix.FlatCmd(nil, "SET", key, value, "EX", remaining, "NX")); err != nil {
		log.WithError(err).WithField("jti", jtiRefresh).Warn("refresh rotation: Redis SET failed, degrading to signature-only validation")
		res.Degraded = true
		res.DegradedReason = "redis error: " + err.Error()
		return res
	}

	res.Rotated = true
	return res
}

// --- JWT blacklist ---

// IsTokenAllowed returns true when the token is not in the blacklist.
//
// Dependency: JWT, Redis database + enable 'INVALIDATE_JWT' in .env
func IsTokenAllowed(jti string) bool {
	// verify that JWT service is enabled in .env
	if !config.IsJWT() {
		return true
	}

	// Redis not available, abort
	if !config.IsRedis() {
		return true
	}

	// token blacklist management not enabled, abort
	if !config.InvalidateJWT() {
		return true
	}

	jti = config.PrefixJtiBlacklist + jti

	client := database.GetRedis()
	rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
	defer cancel()

	// is key available in Redis
	result := 0
	if err := client.Do(ctx, radix.FlatCmd(&result, "EXISTS", jti)); err != nil {
		log.WithError(err).Error("error code: 501")
		return false
	}

	// key found in blacklist
	if result != 0 {
		return false
	}

	// key not found in blacklist
	return true
}

// JWTBlacklistChecker validates a token against the blacklist.
func JWTBlacklistChecker() gin.HandlerFunc {
	return func(c *gin.Context) {
		var jti string
		jtiAccess := strings.TrimSpace(c.GetString("jtiAccess"))
		jtiRefresh := strings.TrimSpace(c.GetString("jtiRefresh"))

		if jtiAccess != "" {
			jti = jtiAccess
			goto CheckBlackList
		}
		if jtiRefresh != "" {
			jti = jtiRefresh
			goto CheckBlackList
		}

	CheckBlackList:
		if !IsTokenAllowed(jti) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "invalid token")
			return
		}

		c.Next()
	}
}
