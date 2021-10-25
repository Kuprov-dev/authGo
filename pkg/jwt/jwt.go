package jwt

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/models"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenCreatorFunc func(username string, secretKey string) (string, time.Time, error)

type Claims struct {
	Username string
	jwt.StandardClaims
}

// фабрика по произвоству ф-ций генераторов токена
func createToken(expirationDelta time.Duration) TokenCreatorFunc {
	return func(username, secretKey string) (string, time.Time, error) {
		expirationTime := time.Now().Add(expirationDelta)
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
	accessExpirationDelta := 1 * time.Minute
	refreshExpirationDelta := 1 * time.Hour

	CreateAccessToken = createToken(accessExpirationDelta)
	CreateRefreshToken = createToken(refreshExpirationDelta)
}

func TokenIsExpired(tokenStr string, secretKey string, resfresh bool) (bool, error, string) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return false, err, claims.Username
	}
	if !token.Valid {
		return false, err, claims.Username
	}
	if resfresh == true {
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < 60*time.Minute {
			return false, nil, claims.Username
		}
	} else {
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < 5*time.Minute {
			return false, nil, claims.Username
		}
	}
	return true, nil, claims.Username
}

func userRefreshTokenMatches(username, refreshToken string, userDAO db.UserDAO) bool {
	userRefreshToken := userDAO.GetRefreshToken(username)
	if userRefreshToken == "" {
		return false
	}
	return userRefreshToken == refreshToken
}

func RefreshTokens(username string, refreshToken string, config *conf.Config, userDAO db.UserDAO) (*models.RefreshedTokenCreds, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(config.SecretKeyRefresh), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, err
	}

	userRefreshToken := userDAO.GetRefreshToken(username)

	if userRefreshToken == "" {
		return nil, fmt.Errorf("User refresh token is empty.")
	}

	token, err = jwt.ParseWithClaims(userRefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(config.SecretKeyRefresh), nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		if !userRefreshTokenMatches(username, refreshToken, userDAO) {
			return nil, fmt.Errorf("Error when matching user DB refresh token with incoming value.")
		}

		accessToken, accessExpirationTime, err1 := CreateAccessToken(username, config.SecretKeyAccess)
		refreshToken, refreshExpirationTime, err2 := CreateRefreshToken(username, config.SecretKeyRefresh)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("Error when creating new JWT token pair.")
		}
		userDAO.UpdateRefreshToken(username, refreshToken)

		creds := &models.RefreshedTokenCreds{
			AccessToken:           accessToken,
			RefreshedToken:        refreshToken,
			AccessExpirationTime:  accessExpirationTime,
			RefreshExpirationTime: refreshExpirationTime,
		}
		return creds, nil
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			err = fmt.Errorf("RefreshToken is not valid JWT")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			err = fmt.Errorf("Refresh token is expired.")
		} else {
			err = fmt.Errorf("Couldn't handle refresh token..")
		}
	} else {
		err = fmt.Errorf("Couldn't handle refresh token..")
	}

	userDAO.UpdateRefreshToken(username, "")
	return nil, err
}

func refreshTokenHeaders(w *http.ResponseWriter, refreshedTokenCreds *models.RefreshedTokenCreds) {
	http.SetCookie(*w, &http.Cookie{
		Name:     "Access",
		Value:    refreshedTokenCreds.AccessToken,
		Path:     "/",
		Expires:  refreshedTokenCreds.AccessExpirationTime,
		HttpOnly: true,
	})
	http.SetCookie(*w, &http.Cookie{
		Name:     "Refresh",
		Value:    refreshedTokenCreds.RefreshedToken,
		Path:     "/",
		Expires:  refreshedTokenCreds.RefreshExpirationTime,
		HttpOnly: true,
	})
}
