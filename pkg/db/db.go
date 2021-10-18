package db

import "auth_service/pkg/models"

type UserDAO interface {
	GetByUsername(username string) *models.User
	UpdateRefreshToken(username string, refreshToken string) *models.User
}

var Users map[string]models.User

func init() {
	Users = map[string]models.User{
		"user1": {
			Username: "user1",
			Password: "password1",
		},
		"user2": {
			Username: "user2",
			Password: "password2",
		},
		"user3": {
			Username: "user3",
			Password: "password3",
		},
	}
}

type InMemroyUserDAO struct {
}

func (*InMemroyUserDAO) GetByUsername(username string) *models.User {
	user, ok := Users[username]
	if !ok {
		return nil
	}

	return &user
}

func (*InMemroyUserDAO) UpdateRefreshToken(username string, refreshToken string) *models.User {
	user, ok := Users[username]
	if !ok {
		return nil
	}

	user.RefreshToken = refreshToken

	return &user
}
