package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenCreatorFunc func(string, string, string) (string, time.Time, error)

type Claims struct {
	Username string
	jwt.StandardClaims
}

// фабрика по произвоству ф-ций генераторов токена
func createToken(expirationTime time.Time) TokenCreatorFunc {
	return func(username, password, secretKey string) (string, time.Time, error) {
		claims := &Claims{
			Username: username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			return "", time.Time{}, err
		}

		return tokenString, expirationTime, nil
	}
}

var CreateAccessToken TokenCreatorFunc
var CreateRefreshToken TokenCreatorFunc

func init() {
	accessExpirationTime := time.Now().Add(1 * time.Minute)
	refreshExpirationTime := time.Now().Add(1 * time.Hour)

	CreateAccessToken = createToken(accessExpirationTime)
	CreateRefreshToken = createToken(refreshExpirationTime)
}

func TokenIsExpired(tokenStr string, secretKey string) (bool, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return false, err
	}

	fmt.Println(token)
	return true, nil
}
