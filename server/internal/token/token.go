package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"time"
)

const (
	ScopeAuth    = "authentication"
	ScopeDeploy  = "deployment"
	ScopeRefresh = "refresh"
)

// Token duration constants
const (
	AuthTokenDuration    = 2 * time.Hour      // 2 hours for regular auth
	DeployTokenDuration  = 4 * time.Hour      // 4 hours for deployments (static sites deploy quickly)
	RefreshTokenDuration = 7 * 24 * time.Hour // 7 days for refresh tokens
)

type Token struct {
	PlainText string    `json:"token"`
	Hash      []byte    `json:"-"`
	UserID    int       `json:"-"`
	Expiry    time.Time `json:"expiry"`
	Scope     string    `json:"-"`
}

func GenerateToken(userID int, ttl time.Duration, scope string) (*Token, error) {
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
		Scope:  scope,
	}

	emptyByte := make([]byte, 32)
	_, err := rand.Read(emptyByte)
	if err != nil {
		return nil, err
	}
	token.PlainText = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(emptyByte)
	hash := sha256.Sum256([]byte(token.PlainText))
	token.Hash = hash[:]
	return token, nil
}
