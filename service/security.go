package service

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mediocregopher/radix/v4"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pilinux/gorest/config"
	"github.com/pilinux/gorest/database"
	"github.com/pilinux/gorest/database/model"
)

// --- Account lockout ---

// useRedisForLockout reports whether Redis should be used for lockout state.
// When Redis is not enabled/available the caller should fall back to
// the next tier (RDBMS, then in-memory).
func useRedisForLockout() bool {
	if !config.IsRedis() {
		return false
	}
	return database.GetRedis() != nil
}

// useRDBMSForLockout reports whether the RDBMS fallback is available.
func useRDBMSForLockout() bool {
	if !config.IsRDBMS() {
		return false
	}
	return database.GetDB() != nil
}

// rdbmsGetLockoutLoad loads the current lockout state from the relational database.
// If the row does not exist it returns zero values and ok=false.
// If the stored lock has already expired the row is reset on the fly (lazy expiry).
func rdbmsLockoutLoad(authID uint64) (attempts int, lockUntil time.Time, ok bool, err error) {
	db := database.GetDB()
	var row model.LoginAttempt
	if rerr := db.Where("auth_id = ?", authID).First(&row).Error; rerr != nil {
		if errors.Is(rerr, gorm.ErrRecordNotFound) {
			return 0, time.Time{}, false, nil
		}
		return 0, time.Time{}, false, rerr
	}

	now := time.Now()
	// lazy expiry: lock has passed -> reset the row atomically?
	// We do a best-effort reset here and now + return non-lazy reset in Update so subsequent writes will also handle it.
	if row.LockUntil != nil && !row.LockUntil.IsZero() && row.LockUntil.Before(now) {
		// non-blocking best-effort reset
		_ = db.Model(&model.LoginAttempt{}).
			Where("auth_id = ? AND lock_until < ?", authID, now).
			Updates(map[string]any{"attempts": 0, "lock_until": nil, "updated_at": now}).
			Error
		return 0, time.Time{}, false, nil
	}

	attempts = row.Attempts
	if row.LockUntil != nil {
		lockUntil = *row.LockUntil
	}
	return attempts, lockUntil, true, nil
}

// rdbmsLockoutIncrement atomically increments the failed-attempt counter in
// the relational database. It returns the new attempt count and whether the
// account has just become locked as a result of this call.
func rdbmsLockoutIncrement(authID uint64) (attempts int, lockedNow bool, err error) {
	db := database.GetDB()
	lockDuration := time.Duration(model.AccountLockDurationMinutes) * time.Minute
	maxAttempts := model.MaxLoginAttempts
	now := time.Now()

	// Ensure a row exists (upsert semantics via FirstOrCreate is racy but acceptable
	// because the subsequent update is atomic).
	var row model.LoginAttempt
	if cerr := db.Where("auth_id = ?", authID).
		Attrs(model.LoginAttempt{Attempts: 0, UpdatedAt: now}).
		FirstOrCreate(&row).Error; cerr != nil {
		// Try a plain insert in case FirstOrCreate failed
		// We don't return yet: maybe it was a race; fall through and attempt the update.
		log.WithError(cerr).WithField("authID", authID).Warn("lockout: RDBMS FirstOrCreate failed, continuing with atomic update")
	}

	// Atomically increment attempts and bump updated_at.
	// If the lock has expired also reset it first.
	result := db.Model(&model.LoginAttempt{}).
		Where("auth_id = ?", authID).
		UpdateColumns(map[string]any{
			"attempts":   gorm.Expr("attempts + ?", 1),
			"updated_at": now,
		})
	if result.Error != nil {
		return 0, false, result.Error
	}

	// Read back the new value.
	var updated model.LoginAttempt
	if rerr := db.Where("auth_id = ?", authID).First(&updated).Error; rerr != nil {
		return 0, false, rerr
	}
	attempts = updated.Attempts

	// Threshold reached? -> set lock (idempotent)
	if attempts >= maxAttempts {
		until := now.Add(lockDuration)
		// Use "SET lock_until = GREATEST(lock_until, ?)" to not shorten an existing lock.
		res := db.Model(&model.LoginAttempt{}).
			Where("auth_id = ? AND (lock_until IS NULL OR lock_until < ?)", authID, until).
			Updates(map[string]any{"lock_until": until, "updated_at": now})
		if res.Error != nil {
			log.WithError(res.Error).WithField("authID", authID).Warn("lockout: RDBMS set lock_until failed")
			return attempts, false, res.Error
		}
		if res.RowsAffected > 0 {
			lockedNow = true
		}
	}

	return attempts, lockedNow, nil
}

// rdbmsLockoutReset clears the failed-login counter and any active lock
// stored in the relational database.
func rdbmsLockoutReset(authID uint64) error {
	db := database.GetDB()
	return db.Where("auth_id = ?", authID).Delete(&model.LoginAttempt{}).Error
}

// IsAccountLocked reports whether the given authID is currently locked out.
//
// Tiers (first available):
//  1. Redis  (best performance, multi-process safe)
//  2. RDBMS  (multi-process safe, used when Redis is unavailable)
//  3. Memory (single-process only, final fallback)
//
// A failure of an error means the backend could not be queried; callers are expected
// to treat such failures as "not locked" to avoid outages taking down the
// login path.
func IsAccountLocked(authID uint64) (locked bool, lockUntil time.Time, err error) {
	if authID == 0 {
		return false, time.Time{}, nil
	}

	// --- Tier 1: Redis
	if useRedisForLockout() {
		client := database.GetRedis()
		rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
		defer cancel()

		lockKey := model.AccountLockKeyPrefix + strconv.FormatUint(authID, 10)
		exists := 0
		if rErr := client.Do(ctx, radix.FlatCmd(&exists, "EXISTS", lockKey)); rErr == nil && exists > 0 {
			ttlSec := -2
			_ = client.Do(ctx, radix.FlatCmd(&ttlSec, "TTL", lockKey))
			until := time.Time{}
			if ttlSec > 0 {
				until = time.Now().Add(time.Duration(ttlSec) * time.Second)
			}
			return true, until, nil
		} else if rErr != nil {
			log.WithError(rErr).WithField("authID", authID).Warn("lockout: Redis EXISTS failed, falling back to RDBMS")
			// fall through
		} else {
			return false, time.Time{}, nil
		}
	}

	// --- Tier 2: RDBMS
	if useRDBMSForLockout() {
		attempts, lockUntilDB, ok, rerr := rdbmsLockoutLoad(authID)
		if rerr == nil {
			if ok && !lockUntilDB.IsZero() && lockUntilDB.After(time.Now()) {
				return true, lockUntilDB, nil
			}
			_ = attempts
			return false, time.Time{}, nil
		}
		log.WithError(rerr).WithField("authID", authID).Warn("lockout: RDBMS load failed, falling back to in-memory")
		// fall through
	}

	// --- Tier 3: in-memory
	attempts, lockUntilMem, ok := model.InMemoryLockout.Get(authID)
	_ = attempts
	if ok && !lockUntilMem.IsZero() && lockUntilMem.After(time.Now()) {
		return true, lockUntilMem, nil
	}
	return false, time.Time{}, nil
}

// RecordFailedLogin increments the failed-login counter for authID.
//
// It returns the new attempt count and whether the account has just become
// locked as a result of this call.
//
// Redis is preferred; on failure RDBMS is tried; on RDBMS failure the
// in-memory store is used. Errors are logged but never returned to the
// caller so that a backend outage never breaks the login flow.
func RecordFailedLogin(authID uint64) (attempts int, lockedNow bool) {
	if authID == 0 {
		return 0, false
	}

	lockDuration := time.Duration(model.AccountLockDurationMinutes) * time.Minute
	maxAttempts := model.MaxLoginAttempts

	// --- Tier 1: Redis
	if useRedisForLockout() {
		client := database.GetRedis()
		if client != nil {
			rConnTTL := config.GetConfig().Database.REDIS.Conn.ConnTTL
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rConnTTL)*time.Second)
			defer cancel()

			attemptKey := model.LoginAttemptKeyPrefix + strconv.FormatUint(authID, 10)
			lockKey := model.AccountLockKeyPrefix + strconv.FormatUint(authID, 10)

			newCount := 0
			if err := client.Do(ctx, radix.FlatCmd(&newCount, "INCR", attemptKey)); err == nil {
				attempts = newCount
				ttlSec := int(lockDuration.Seconds())
				_ = client.Do(ctx, radix.FlatCmd(nil, "EXPIRE", attemptKey, ttlSec))

				if attempts >= maxAttempts {
					ok := ""
					if sErr := client.Do(ctx, radix.FlatCmd(&ok, "SET", lockKey, "1", "EX", ttlSec, "NX")); sErr == nil && ok == "OK" {
						lockedNow = true
					}
				}
				return attempts, lockedNow
			}
			log.WithError(err).WithField("authID", authID).Warn("lockout: Redis INCR failed, falling back to RDBMS")
		}
	}

	// --- Tier 2: RDBMS
	if useRDBMSForLockout() {
		att, locked, rerr := rdbmsLockoutIncrement(authID)
		if rerr == nil {
			return att, locked
		}
		log.WithError(rerr).WithField("authID", authID).Warn("lockout: RDBMS increment failed, falling back to in-memory")
		// fall through
	}

	// --- Tier 3: in-memory
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
//
// It clears state from all available tiers (Redis, RDBMS, in-memory) so that
// no stale lockout data is left behind when switching backends.
func ResetLoginAttempts(authID uint64) {
	if authID == 0 {
		return
	}

	// --- Tier 1: Redis
	if config.IsRedis() {
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

	// --- Tier 2: RDBMS
	if config.IsRDBMS() {
		if err := rdbmsLockoutReset(authID); err != nil {
			log.WithError(err).WithField("authID", authID).Warn("lockout: RDBMS reset failed")
		}
	}

	// --- Tier 3: in-memory
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
