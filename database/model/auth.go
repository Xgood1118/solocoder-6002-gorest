// Package model contains all the models required
// for a functional database management system.
package model

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/pilinux/gorest/config"
	"github.com/pilinux/gorest/lib"
)

// Email verification statuses
const (
	EmailNotVerified       int8 = -1
	EmailVerifyNotRequired int8 = 0
	EmailVerified          int8 = 1
)

// Email type
const (
	EmailTypeVerifyEmailNewAcc  int = 1 // verify email of newly registered user
	EmailTypePassRecovery       int = 2 // password recovery code
	EmailTypeVerifyUpdatedEmail int = 3 // verify request of updating user email
)

// Redis key prefixes
const (
	EmailVerificationKeyPrefix string = "gorest-email-verification-"
	EmailUpdateKeyPrefix       string = "gorest-email-update-"
	PasswordRecoveryKeyPrefix  string = "gorest-pass-recover-" // #nosec G101 —- Redis key prefix only; contains no secret credentials

	LoginAttemptKeyPrefix  string = "gorest-login-attempt-"
	AccountLockKeyPrefix   string = "gorest-account-lock-"
)

// MaxLoginAttempts is the maximum number of consecutive failed login attempts
// before the account is temporarily locked.
const MaxLoginAttempts = 5

// AccountLockDurationMinutes is the duration (in minutes) an account remains
// locked after exceeding the maximum failed login attempts.
const AccountLockDurationMinutes = 15

// Auth represents the auths table.
type Auth struct {
	AuthID      uint64         `gorm:"primaryKey" json:"authID,omitempty"`
	CreatedAt   time.Time      `json:"createdAt,omitzero"`
	UpdatedAt   time.Time      `json:"updatedAt,omitzero"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Email       string         `gorm:"index" json:"email"`
	EmailCipher string         `json:"-"`
	EmailNonce  string         `json:"-"`
	EmailHash   string         `gorm:"index" json:"-"`
	Password    string         `json:"password"` // #nosec G117 -- used for input only, custom MarshalJSON excludes it from output
	VerifyEmail int8           `json:"-"`

	LastLoginIP *string    `gorm:"column:last_login_ip" json:"lastLoginIP,omitempty"`
	LastLoginUA *string    `gorm:"column:last_login_ua" json:"lastLoginUA,omitempty"`
	LastLoginAt *time.Time `gorm:"column:last_login_at" json:"lastLoginAt,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for Auth.
func (v *Auth) UnmarshalJSON(b []byte) error {
	aux := struct {
		AuthID   uint64 `json:"authID"`
		Email    string `json:"email"`
		Password string `json:"password"` // #nosec G117 -- internal unmarshal helper, password is hashed before storage
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	configSecurity := config.GetConfig().Security

	// check password length
	// if more checks are required i.e. password pattern,
	// add all conditions here
	if len(aux.Password) < configSecurity.UserPassMinLength {
		return errors.New("short password")
	}

	v.AuthID = aux.AuthID
	v.Email = strings.TrimSpace(aux.Email)

	config := lib.HashPassConfig{
		Memory:      configSecurity.HashPass.Memory,
		Iterations:  configSecurity.HashPass.Iterations,
		Parallelism: configSecurity.HashPass.Parallelism,
		SaltLength:  configSecurity.HashPass.SaltLength,
		KeyLength:   configSecurity.HashPass.KeyLength,
	}
	pass, err := lib.HashPass(config, aux.Password, configSecurity.HashSec)
	if err != nil {
		return err
	}
	v.Password = pass

	return nil
}

// MarshalJSON implements the json.Marshaler interface for Auth.
func (v Auth) MarshalJSON() ([]byte, error) {
	aux := struct {
		AuthID      uint64     `json:"authID"`
		Email       string     `json:"email"`
		CreatedAt   *time.Time `json:"createdAt,omitempty"`
		UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
		LastLoginIP *string    `json:"lastLoginIP,omitempty"`
		LastLoginUA *string    `json:"lastLoginUA,omitempty"`
		LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	}{
		AuthID:      v.AuthID,
		Email:       strings.TrimSpace(v.Email),
		LastLoginIP: v.LastLoginIP,
		LastLoginUA: v.LastLoginUA,
		LastLoginAt: v.LastLoginAt,
	}

	if !v.CreatedAt.IsZero() {
		t := v.CreatedAt
		aux.CreatedAt = &t
	}
	if !v.UpdatedAt.IsZero() {
		t := v.UpdatedAt
		aux.UpdatedAt = &t
	}

	return json.Marshal(aux)
}

// AuthPayload holds all auth-related request data.
type AuthPayload struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"` // #nosec G117 -- request payload only, never stored or returned with sensitive data

	VerificationCode string `json:"verificationCode,omitempty"`

	OTP string `json:"otp,omitempty"`

	SecretCode  string `json:"secretCode,omitempty"`
	RecoveryKey string `json:"recoveryKey,omitempty"`

	PassNew    string `json:"passNew,omitempty"`
	PassRepeat string `json:"passRepeat,omitempty"`
}

// TempEmail represents the temp_emails table used to hold data temporarily
// during the process of replacing a user's email address
// with a new one.
type TempEmail struct {
	ID          uint64    `gorm:"primaryKey" json:"-"`
	CreatedAt   time.Time `json:"createdAt,omitzero"`
	UpdatedAt   time.Time `json:"updatedAt,omitzero"`
	Email       string    `gorm:"index" json:"emailNew"`
	Password    string    `gorm:"-" json:"password,omitempty"` // #nosec G117 -- value not from DB, only used for validation
	EmailCipher string    `json:"-"`
	EmailNonce  string    `json:"-"`
	EmailHash   string    `gorm:"index" json:"-"`
	IDAuth      uint64    `gorm:"index" json:"-"`
}

// LoginAttempt tracks per-auth failed-login counters and temporary lock state.
//
// It is the RDBMS-backed fallback for account lockout when Redis is not
// available, ensuring multi-process deployments still coordinate attempt
// counts correctly.
type LoginAttempt struct {
	AuthID    uint64     `gorm:"primaryKey;column:auth_id" json:"authID"`
	Attempts  int        `gorm:"column:attempts;not null;default:0" json:"attempts"`
	LockUntil *time.Time `gorm:"column:lock_until" json:"lockUntil,omitempty"`
	UpdatedAt time.Time  `gorm:"column:updated_at" json:"updatedAt,omitzero"`
}
