package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
)

// for futher implementation
func hashPassword(password string, config *conf.Config) string {
	return password
}

func checkUserPassowrd(username, password string, userRepo db.UserDAO, config *conf.Config) bool {
	user := userRepo.GetByUsername(username)
	if user == nil {
		return false
	}
	return user.Password == hashPassword(password, config)
}
