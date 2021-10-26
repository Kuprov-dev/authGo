package auth

import (
	"auth_service/pkg/db"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func checkUserPassowrd(username, password string, userRepo db.UserDAO) bool {
	user := userRepo.GetByUsername(username)
	if user == nil {
		return false
	}
	return CheckPasswordHash(password, user.Password)
}
