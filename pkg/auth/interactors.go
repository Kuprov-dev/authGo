package auth

import "auth_service/pkg/db"

func checkUserPassowrd(username, password string, userRepo db.UserDAO) bool {
	user := userRepo.GetByUsername(username)
	if user == nil {
		return false
	}
	return user.Password == password
}
