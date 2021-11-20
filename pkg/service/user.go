package service

import (
	"context"
)

type User struct {
	ID       string
	Username string
	Password string
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	return s.userStorage.ListUsers(ctx)
}

//func (s *Service) CreateUser(ctx context.Context, user *User) error {
//	user.ID =
//
//	return s.userStorage.CreateUser(ctx, user)
//}
