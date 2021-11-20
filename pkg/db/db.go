package db

import (
	"auth_service/pkg/models"
	"go.mongodb.org/mongo-driver/mongo"
)

//create database search for searching users and generate uuid
type UserDAO interface {
	GetByUsername(username string) *models.User
	UpdateRefreshToken(username string, refreshToken string) *models.User
	GetRefreshToken(username string) string
}

var Users map[string]*models.User

type Config struct {
	DBName  string
	ConnStr string
}

type Database struct {
	db             *mongo.Database
	client         *mongo.Client
	userCollection *mongo.Collection
}

func init() {
	Users = map[string]*models.User{
		"user1": {
			Username: "user1",
			Password: "$2a$10$EWGUgDWL9kL6cWIuCjSMxu5ZccORaBifqP/qgFa069zGYnFXHG29S",
		},
		"user2": {
			Username: "user2",
			Password: "$2a$10$EWGUgDWL9kL6cWIuCjSMxu5ZccORaBifqP/qgFa069zGYnFXHG29S",
		},
		"user3": {
			Username: "user3",
			Password: "$2a$10$EWGUgDWL9kL6cWIuCjSMxu5ZccORaBifqP/qgFa069zGYnFXHG29S",
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

	return user
}

func (*InMemroyUserDAO) UpdateRefreshToken(username string, refreshToken string) *models.User {
	user, ok := Users[username]
	if !ok {
		return nil
	}

	user.RefreshToken = refreshToken

	return user
}

func (*InMemroyUserDAO) GetRefreshToken(username string) string {
	user, ok := Users[username]
	if !ok {
		return ""
	}

	return user.RefreshToken
}
