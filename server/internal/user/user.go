package user

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type password struct {
	plainText *string
	hash      []byte
}

func (p *password) Set(plainTextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainTextPassword), 12)
	if err != nil {
		return err
	}
	p.plainText = &plainTextPassword
	p.hash = hash
	return nil
}

func (p *password) Matches(plainTextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.hash, []byte(plainTextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

func (p *password) ClearPlainText() {
	p.plainText = nil
}

func (p *password) IsSet() bool {
	return p.plainText != nil || len(p.hash) > 0
}

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash password   `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
	ApprovedBy   *int64     `json:"-"`
	IsAdmin      bool       `json:"is_admin"`
	Status       string     `json:"status"`
}
