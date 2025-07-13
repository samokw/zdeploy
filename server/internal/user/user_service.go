package user

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrInvalidUsername     = errors.New("invalid username")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrUserNotApproved     = errors.New("user not approved")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrUserAlreadyApproved = errors.New("user already approved")
)

type UserService struct {
	repo UserStore
}

func NewUserService(repo UserStore) *UserService {
	return &UserService{
		repo: repo,
	}
}

func (s *UserService) CreateUser(ctx context.Context, username, password string) (*User, error) {
	if err := s.validateUsername(username); err != nil {
		return nil, err
	}

	if err := s.validatePassword(password); err != nil {
		return nil, err
	}

	existingUser, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	user := &User{
		Username: username,
		Status:   "pending",
		IsAdmin:  false,
	}

	if err := user.PasswordHash.Set(password); err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	user.PasswordHash.ClearPlainText()
	return user, nil
}

func (s *UserService) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	matches, err := user.PasswordHash.Matches(password)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, ErrUnauthorized
	}

	if user.ApprovedAt == nil {
		return nil, ErrUserNotApproved
	}

	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, id int64) (*User, error) {
	user, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *UserService) UpdateUser(ctx context.Context, user *User) error {
	if err := s.validateUsername(user.Username); err != nil {
		return err
	}

	return s.repo.UpdateUser(ctx, user)
}

func (s *UserService) DeleteUser(ctx context.Context, username string) error {
	return s.repo.DeleteUserByUsername(ctx, username)
}

func (s *UserService) ChangePassword(ctx context.Context, username, currentPassword, newPassword string) error {
	user, err := s.AuthenticateUser(ctx, username, currentPassword)
	if err != nil {
		return err
	}

	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	if err := user.PasswordHash.Set(newPassword); err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return s.repo.UpdateUser(ctx, user)
}

// Admin methods
func (s *UserService) ApproveUser(ctx context.Context, userID, approvedBy int64) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	if user.ApprovedAt != nil {
		return ErrUserAlreadyApproved
	}

	approver, err := s.repo.GetUserByID(ctx, approvedBy)
	if err != nil {
		return err
	}
	if approver == nil || !approver.IsAdmin {
		return ErrUnauthorized
	}

	return s.repo.ApproveUser(ctx, userID, approvedBy)
}

func (s *UserService) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.repo.ListUsers(ctx, limit, offset)
}

func (s *UserService) ListPendingUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.repo.ListPendingUsers(ctx, limit, offset)
}

func (s *UserService) MakeAdmin(ctx context.Context, userID, adminID int64) error {
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return err
	}
	if admin == nil || !admin.IsAdmin {
		return ErrUnauthorized
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.IsAdmin = true
	return s.repo.UpdateUser(ctx, user)
}

func (s *UserService) RevokeAdmin(ctx context.Context, userID, adminID int64) error {
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return err
	}
	if admin == nil || !admin.IsAdmin {
		return ErrUnauthorized
	}

	if userID == adminID {
		return errors.New("cannot revoke your own admin privileges")
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.IsAdmin = false
	return s.repo.UpdateUser(ctx, user)
}

func (s *UserService) UpdateUserStatus(ctx context.Context, userID int64, status string, adminID int64) error {
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return err
	}
	if admin == nil || !admin.IsAdmin {
		return ErrUnauthorized
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.Status = status
	return s.repo.UpdateUser(ctx, user)
}

// Validation methods
func (s *UserService) validateUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return ErrInvalidUsername
	}
	if len(username) > 50 {
		return ErrInvalidUsername
	}

	// Allow alphanumeric characters, underscores, and hyphens
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		return ErrInvalidUsername
	}

	return nil
}

func (s *UserService) validatePassword(password string) error {
	if len(password) < 8 {
		return ErrInvalidPassword
	}
	if len(password) > 100 {
		return ErrInvalidPassword
	}

	// Check for at least one uppercase, one lowercase, and one digit
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)

	if !hasUpper || !hasLower || !hasDigit {
		return ErrInvalidPassword
	}

	return nil
}
