package service

import "context"

type UserStorage interface {
	CreateUser(ctx context.Context, user *User) error
	ListUsers(ctx context.Context) ([]User, error)
}
