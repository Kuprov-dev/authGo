package jwt

import (
	"auth_service/pkg/conf"
	"time"

	"github.com/golang-jwt/jwt"
)

type Claims struct {
	Username string
	jwt.StandardClaims
}

func CreateAccessToken(username string, password string, config *conf.Config) (string, time.Time, error) {
	expirationTime := time.Now().Add(1 * time.Minute)

	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.SecretKey))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expirationTime, nil
}

func CreateRefreshToken(username string, password string, config *conf.Config) (string, time.Time, error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.SecretKey))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expirationTime, nil
}
