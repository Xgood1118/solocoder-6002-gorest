package model

import (
	"sync"
	"time"

	"gorm.io/gorm"
)

// TwoFA represents the two_fas table.
type TwoFA struct {
	ID        uint64         `gorm:"primaryKey" json:"-"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	KeyMain   string         `json:"-"`
	KeyBackup string         `json:"-"`
	KeySalt   string         `json:"-"`
	UUIDSHA   string         `json:"-"`
	UUIDEnc   string         `json:"-"`
	Status    string         `json:"-"`
	IDAuth    uint64         `gorm:"index" json:"-"`
}

// TwoFABackup represents the two_fa_backups table.
type TwoFABackup struct {
	ID        uint64    `gorm:"primaryKey" json:"-"`
	CreatedAt time.Time `json:"-"`
	Code      string    `gorm:"-" json:"code"`
	CodeHash  string    `json:"-"`
	IDAuth    uint64    `gorm:"index" json:"-"`
}

// Secret2FA holds encoded secrets temporarily in RAM.
type Secret2FA struct {
	PassHash []byte `json:"-"`
	KeySalt  []byte `json:"-"`
	Secret   []byte `json:"-"`
	Image    string `json:"-"`
}

// cloneSecret2FA returns a deep copy of a Secret2FA.
// This prevents external code from mutating the store's data
// through shared slice backing arrays.
func cloneSecret2FA(v Secret2FA) Secret2FA {
	out := Secret2FA{Image: v.Image}
	if v.PassHash != nil {
		out.PassHash = append([]byte(nil), v.PassHash...)
	}
	if v.KeySalt != nil {
		out.KeySalt = append([]byte(nil), v.KeySalt...)
	}
	if v.Secret != nil {
		out.Secret = append([]byte(nil), v.Secret...)
	}
	return out
}

// Secret2FAStore provides thread-safe access to in-memory 2FA secrets.
type Secret2FAStore struct {
	mu   sync.RWMutex
	data map[uint64]Secret2FA
}

// NewSecret2FAStore creates a new Secret2FAStore.
func NewSecret2FAStore() *Secret2FAStore {
	return &Secret2FAStore{
		data: make(map[uint64]Secret2FA),
	}
}

// Get retrieves a Secret2FA from the store.
func (s *Secret2FAStore) Get(key uint64) (Secret2FA, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return cloneSecret2FA(v), ok
}

// Set stores a Secret2FA in the store.
func (s *Secret2FAStore) Set(key uint64, value Secret2FA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = cloneSecret2FA(value)
}

// Delete removes a Secret2FA from the store.
func (s *Secret2FAStore) Delete(key uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

// InMemorySecret2FA keeps secrets temporarily
// in memory to set up 2FA.
var InMemorySecret2FA = NewSecret2FAStore()

// --- Login attempt / account lockout in-memory store ---

// lockoutEntry holds a failed-attempt count and optional lock-until timestamp.
type lockoutEntry struct {
	Attempts int
	LockUntil time.Time
	UpdatedAt time.Time
}

// LockoutStore is a thread-safe, TTL-aware, bounded in-memory store for
// login-attempt counters and account-lock state. It is used as a fallback
// when Redis is not available.
//
// Note: in multi-process deployments without Redis, attempts are NOT
// coordinated across processes. Operators should either enable Redis or
// understand this limitation.
type LockoutStore struct {
	mu      sync.RWMutex
	data    map[uint64]lockoutEntry
	maxKeys int
}

// NewLockoutStore creates a LockoutStore with the given capacity.
// When maxKeys <= 0 a reasonable default is used.
func NewLockoutStore(maxKeys int) *LockoutStore {
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &LockoutStore{
		data:    make(map[uint64]lockoutEntry),
		maxKeys: maxKeys,
	}
}

// evictOldest removes the oldest entry when the store is over capacity.
func (s *LockoutStore) evictOldest() {
	var oldestAuthID uint64
	var oldestUpdated time.Time
	first := true
	for authID, entry := range s.data {
		if first || entry.UpdatedAt.Before(oldestUpdated) {
			first = false
			oldestAuthID = authID
			oldestUpdated = entry.UpdatedAt
		}
	}
	if !first {
		delete(s.data, oldestAuthID)
	}
}

// Get returns the current attempts and lock-until time for an authID,
// along with whether the entry exists and is fresh.
func (s *LockoutStore) Get(authID uint64) (attempts int, lockUntil time.Time, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.data[authID]
	if !ok {
		return 0, time.Time{}, false
	}
	return entry.Attempts, entry.LockUntil, true
}

// Increment increments the failed-attempt counter for authID.
// If the store is over capacity the oldest entry is evicted first.
func (s *LockoutStore) Increment(authID uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.data[authID]
	if !ok {
		if len(s.data) >= s.maxKeys {
			s.evictOldest()
		}
		entry = lockoutEntry{Attempts: 0}
	}
	entry.Attempts++
	entry.UpdatedAt = time.Now()
	s.data[authID] = entry
	return entry.Attempts
}

// SetLock marks the account as locked until the given time.
func (s *LockoutStore) SetLock(authID uint64, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.data[authID]
	if !ok {
		if len(s.data) >= s.maxKeys {
			s.evictOldest()
		}
	}
	entry.LockUntil = until
	entry.UpdatedAt = time.Now()
	s.data[authID] = entry
}

// Reset resets attempts and lock state for the given authID.
func (s *LockoutStore) Reset(authID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, authID)
}

// CleanupExpired removes entries whose lock-until time has passed and whose
// last update is older than the given TTL. This can be called periodically
// from a background goroutine; it is not required for correctness.
func (s *LockoutStore) CleanupExpired(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-ttl)
	for authID, entry := range s.data {
		if !entry.LockUntil.IsZero() && entry.LockUntil.Before(now) {
			entry.LockUntil = time.Time{}
			entry.Attempts = 0
		}
		if entry.UpdatedAt.Before(cutoff) && entry.LockUntil.IsZero() {
			delete(s.data, authID)
		}
	}
}

// InMemoryLockout is the process-wide fallback lockout store used when
// Redis is unavailable.
var InMemoryLockout = NewLockoutStore(0)
