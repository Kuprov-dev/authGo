package service

import (
	"context"
)

type User struct {
	ID       int
	Username string
	Password string
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	return s.userStorage.ListUsers(ctx)
}

func (s *Service) CreateUser(ctx context.Context, user *User) error {
	user.ID = 228

	return s.userStorage.CreateUser(ctx, user)
}
