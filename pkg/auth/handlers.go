package auth

import (
	"auth_service/pkg/conf"

	"auth_service/pkg/db"
	"auth_service/pkg/errors"
	"auth_service/pkg/jwt"
	"auth_service/pkg/models"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Контроллер логина, конфиг инжектится
func SignInHandler(config *conf.Config, userDAO db.UserDAO, ctx context.Context, dao *db.MongoDBTempDAO) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.LoginCredentials
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			errors.MakeUnathorisedErrorResponse(&w, "Error decoding creds.")
			return
		}
		username := creds.Username
		password := creds.Password
		ok, err := dao.FindUser(ctx, username, password)

		if err != nil {
			//log.Fatal(err)
			errors.MakeUnathorisedErrorResponse(&w, "smth wrong with db")
		}
		if !ok {

			errors.MakeUnathorisedErrorResponse(&w, "no pass")

		}

		accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, config.SecretKeyAccess)

		if err != nil {
			errors.MakeInternalServerErrorResponse(&w, "Error create access token.")
		}

		refreshToken, refreshExpirationTime, err := jwt.CreateRefreshToken(username, config.SecretKeyRefresh)
		if err != nil {
			errors.MakeInternalServerErrorResponse(&w, "Error create refresh token.")
		}

		userDAO.UpdateRefreshToken(username, refreshToken)

		http.SetCookie(w, &http.Cookie{
			Name:     "Access",
			Value:    accessToken,
			Path:     "/",
			Expires:  accessExpirationTime,
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "Refresh",
			Value:    refreshToken,
			Path:     "/",
			Expires:  refreshExpirationTime,
			HttpOnly: true,
		})
	}
}

// Контроллер логаута, конфиг инжектится
func SignOutHandler(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:    "Access",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),

			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:    "Refresh",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),

			HttpOnly: true,
		})
	}
}

// Тестовый хендлер чтоб посмотреть в хедеры
func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Println("hello")
}

func ValidateTokenHeadersHandler(config *conf.Config, userDAO db.UserDAO) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			userCreds, err := jwt.GetUserCredsFromContext(r.Context())
			if err != nil {
				errors.MakeBadRequestErrorResponse(&w, "Couldn't get user creds from context."+err.Error())
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(models.UserDetailResponse{Username: userCreds.Username})
		}
		validateTokenMiddleware := ValidateTokenAndRefreshMiddleware(config, userDAO)
		next := GetTokenCredsFromHeader(validateTokenMiddleware(http.HandlerFunc(handler)))
		next.ServeHTTP(w, r)
	}
}

func ValidateTokensInBodyHandler(config *conf.Config, userDAO db.UserDAO) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			userCreds, err := jwt.GetUserCredsFromContext(r.Context())
			if err != nil {
				errors.MakeBadRequestErrorResponse(&w, "Couldn't get user creds from context."+err.Error())
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(models.UserDetailResponse{Username: userCreds.Username})
		}
		validateTokenMiddleware := ValidateTokenAndRefreshMiddleware(config, userDAO)
		next := GetTokenCredsFromBody(validateTokenMiddleware(http.HandlerFunc(handler)))
		next.ServeHTTP(w, r)
	}
}
