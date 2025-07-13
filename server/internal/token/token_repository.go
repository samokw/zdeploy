package token

import (
	"context"
	"database/sql"
	"time"
)

type TokenRepository interface {
	Insert(ctx context.Context, token *Token) error
	GetByHash(ctx context.Context, hash []byte) (*Token, error)
	CreateNewToken(ctx context.Context, userId int, ttl time.Duration, scope string) (*Token, error)
	DeleteAllTokensForUser(ctx context.Context, userID int, scope string) error
	DeleteTokenByHash(ctx context.Context, hash []byte) error
}

type TokenRepo struct {
	db *sql.DB
}

func NewTokenRepo(db *sql.DB) *TokenRepo {
	return &TokenRepo{
		db: db,
	}
}

func (t *TokenRepo) CreateNewToken(ctx context.Context, userID int, ttl time.Duration, scope string) (*Token, error) {
	token, err := GenerateToken(userID, ttl, scope)
	if err != nil {
		return nil, err
	}
	err = t.Insert(ctx, token)
	return token, err
}

func (t *TokenRepo) Insert(ctx context.Context, token *Token) error {
	query := `
	INSERT INTO tokens (hash, user_id, expiry, scope)
	VALUES ($1, $2, $3, $4)
	`
	_, err := t.db.ExecContext(ctx, query, token.Hash, token.UserID, token.Expiry, token.Scope)
	if err != nil {
		return err
	}
	return nil
}

func (t *TokenRepo) DeleteAllTokensForUser(ctx context.Context, userID int, scope string) error {
	query := `
	DELETE FROM tokens
	WHERE scope = $1 AND user_id = $2
	`
	_, err := t.db.ExecContext(ctx, query, scope, userID)
	return err
}

func (t *TokenRepo) DeleteTokenByHash(ctx context.Context, hash []byte) error {
	query := `
	DELETE FROM tokens
	WHERE hash = $1
	`
	_, err := t.db.ExecContext(ctx, query, hash)
	return err
}

func (t *TokenRepo) GetByHash(ctx context.Context, hash []byte) (*Token, error) {
	query := `
	SELECT hash, user_id, expiry, scope
	FROM tokens
	WHERE hash = $1
	`

	token := &Token{}
	err := t.db.QueryRowContext(ctx, query, hash).Scan(
		&token.Hash,
		&token.UserID,
		&token.Expiry,
		&token.Scope,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	return token, nil
}
