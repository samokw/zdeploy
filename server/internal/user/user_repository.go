package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"time"
)

type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUserByUsername(ctx context.Context, username string) error
	GetUserToken(ctx context.Context, scope, tokenPlainText string) (*User, error)

	// Admin methods
	ApproveUser(ctx context.Context, userID, approvedBy int64) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	ListPendingUsers(ctx context.Context, limit, offset int) ([]*User, error)
}

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{
		db: db,
	}
}

func (ur *UserRepo) CreateUser(ctx context.Context, user *User) error {
	query := `
	INSERT INTO users (username, password_hash, status, is_admin)
	VALUES ($1, $2, $3, $4)
	RETURNING id, created_at
	`
	err := ur.db.QueryRowContext(ctx, query,
		user.Username,
		user.PasswordHash.hash,
		user.Status,
		user.IsAdmin,
	).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (ur *UserRepo) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{
		PasswordHash: password{},
	}
	query := `
	SELECT id, username, password_hash, created_at, approved_at, approved_by, is_admin, status
	FROM users
	WHERE username = $1
	`
	err := ur.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash.hash,
		&user.CreatedAt,
		&user.ApprovedAt,
		&user.ApprovedBy,
		&user.IsAdmin,
		&user.Status,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ur *UserRepo) UpdateUser(ctx context.Context, user *User) error {
	query := `
	UPDATE users
	SET username = $1, status = $2, is_admin = $3, approved_at = $4, approved_by = $5
	WHERE id = $6
	`
	result, err := ur.db.ExecContext(ctx, query,
		user.Username,
		user.Status,
		user.IsAdmin,
		user.ApprovedAt,
		user.ApprovedBy,
		user.ID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ur *UserRepo) DeleteUserByUsername(ctx context.Context, username string) error {
	query := `
	DELETE FROM users
	WHERE username = $1
	`
	result, err := ur.db.ExecContext(ctx, query, username)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ur *UserRepo) GetUserToken(ctx context.Context, scope, tokenPlainText string) (*User, error) {
	tokenHash := sha256.Sum256([]byte(tokenPlainText))

	query := `
	SELECT u.id, u.username, u.password_hash, u.created_at, u.approved_at, u.approved_by, u.is_admin, u.status
	FROM users u
	INNER JOIN tokens t ON t.user_id = u.id
	WHERE t.hash = $1 AND t.scope = $2 AND t.expiry > $3
	`
	user := &User{
		PasswordHash: password{},
	}

	err := ur.db.QueryRowContext(ctx, query, tokenHash[:], scope, time.Now()).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash.hash,
		&user.CreatedAt,
		&user.ApprovedAt,
		&user.ApprovedBy,
		&user.IsAdmin,
		&user.Status,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Admin-specific methods
func (ur *UserRepo) GetUserByID(ctx context.Context, id int64) (*User, error) {
	user := &User{
		PasswordHash: password{},
	}
	query := `
	SELECT id, username, password_hash, created_at, approved_at, approved_by, is_admin, status
	FROM users
	WHERE id = $1
	`
	err := ur.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash.hash,
		&user.CreatedAt,
		&user.ApprovedAt,
		&user.ApprovedBy,
		&user.IsAdmin,
		&user.Status,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ur *UserRepo) ApproveUser(ctx context.Context, userID, approvedBy int64) error {
	query := `
	UPDATE users
	SET approved_at = CURRENT_TIMESTAMP, approved_by = $1
	WHERE id = $2
	`
	result, err := ur.db.ExecContext(ctx, query, approvedBy, userID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ur *UserRepo) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	query := `
	SELECT id, username, password_hash, created_at, approved_at, approved_by, is_admin, status
	FROM users
	ORDER BY created_at DESC
	LIMIT $1 OFFSET $2
	`
	rows, err := ur.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{
			PasswordHash: password{},
		}
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.PasswordHash.hash,
			&user.CreatedAt,
			&user.ApprovedAt,
			&user.ApprovedBy,
			&user.IsAdmin,
			&user.Status,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (ur *UserRepo) ListPendingUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	query := `
	SELECT id, username, password_hash, created_at, approved_at, approved_by, is_admin, status
	FROM users
	WHERE approved_at IS NULL
	ORDER BY created_at DESC
	LIMIT $1 OFFSET $2
	`
	rows, err := ur.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{
			PasswordHash: password{},
		}
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.PasswordHash.hash,
			&user.CreatedAt,
			&user.ApprovedAt,
			&user.ApprovedBy,
			&user.IsAdmin,
			&user.Status,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
