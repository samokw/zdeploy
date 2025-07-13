package token

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
	ErrInvalidScope  = errors.New("invalid token scope")
)

type TokenService struct {
	repo TokenRepository
}

func NewTokenService(repo TokenRepository) *TokenService {
	return &TokenService{
		repo: repo,
	}
}

func (s *TokenService) CreateAuthToken(ctx context.Context, userID int, ttl time.Duration) (*Token, error) {
	err := s.repo.DeleteAllTokensForUser(ctx, userID, ScopeAuth)
	if err != nil {
		return nil, err
	}

	token, err := s.repo.CreateNewToken(ctx, userID, ttl, ScopeAuth)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *TokenService) ValidateToken(ctx context.Context, plaintext string, scope string) (*Token, error) {
	hash := sha256.Sum256([]byte(plaintext))

	token, err := s.repo.GetByHash(ctx, hash[:])
	if err != nil {
		return nil, ErrTokenNotFound
	}

	if time.Now().After(token.Expiry) {
		return nil, ErrTokenExpired
	}

	if token.Scope != scope {
		return nil, ErrInvalidScope
	}

	return token, nil
}

func (s *TokenService) RevokeToken(ctx context.Context, hash []byte) error {
	return s.repo.DeleteTokenByHash(ctx, hash)
}

func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID int, scope string) error {
	return s.repo.DeleteAllTokensForUser(ctx, userID, scope)
}

func (s *TokenService) CreateAuthTokenWithRefresh(ctx context.Context, userID int64) (*Token, *Token, error) {
	// Create short-lived auth token
	authToken, err := s.repo.CreateNewToken(ctx, int(userID), AuthTokenDuration, ScopeAuth)
	if err != nil {
		return nil, nil, err
	}

	// Create long-lived refresh token
	refreshToken, err := s.repo.CreateNewToken(ctx, int(userID), RefreshTokenDuration, ScopeRefresh)
	if err != nil {
		return nil, nil, err
	}

	return authToken, refreshToken, nil
}

func (s *TokenService) RefreshAuthToken(ctx context.Context, refreshTokenPlaintext string) (*Token, error) {
	// Validate refresh token
	refreshToken, err := s.ValidateToken(ctx, refreshTokenPlaintext, ScopeRefresh)
	if err != nil {
		return nil, err
	}

	// Create new auth token
	authToken, err := s.repo.CreateNewToken(ctx, refreshToken.UserID, AuthTokenDuration, ScopeAuth)
	if err != nil {
		return nil, err
	}

	return authToken, nil
}

func (s *TokenService) CreateDeployToken(ctx context.Context, userID int64) (*Token, error) {
	// Delete existing deploy tokens for this user
	err := s.repo.DeleteAllTokensForUser(ctx, int(userID), ScopeDeploy)
	if err != nil {
		return nil, err
	}

	// Create new deploy token
	token, err := s.repo.CreateNewToken(ctx, int(userID), DeployTokenDuration, ScopeDeploy)
	if err != nil {
		return nil, err
	}

	return token, nil
}
