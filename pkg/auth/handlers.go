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

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}
type ContextKeyBody string

var ContextUser ContextKeyBody = "tokenCreds"

// Контроллер логина, конфиг инжектится
func SignInHandler(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds Credentials
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		username := creds.Username
		password := creds.Password

		userDAO := db.InMemroyUserDAO{}
		ok := checkUserPassowrd(username, password, &userDAO)

		if !ok {
			errors.MakeUnathorisedErrorResponse(&w, "")
			return
		}

		accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, config.SecretKeyAccess)

		if err != nil {
			errors.MakeInternalServerErrorResponse(&w, "")
		}

		refreshToken, refreshExpirationTime, err := jwt.CreateRefreshToken(username, config.SecretKeyRefresh)
		if err != nil {
			fmt.Println(refreshToken, err)
			errors.MakeInternalServerErrorResponse(&w, "")
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

// Тестовая ручка чтоб посмотреть в хедеры и заюзать мидлварь
func Test(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("MIDDLEWARE!")
		next := CheckRefreshToken(Hello, config)
		next.ServeHTTP(w, r)
	}
}

func ValidateTokenHeadersHandler(config *conf.Config, userDAO db.UserDAO) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ContextUser = "Tokens"
		middleware := jwt.ValidateTokenMiddleware(config, userDAO, "Tokens")
		//здесь задается рефреш токен
		creds := &models.TokenCredentials{
			AccessToken:  r.Header.Get("Access"),
			RefreshToken: r.Header.Get("Refresh"),
		}
		setValue := func(r *http.Request, val models.TokenCredentials) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), "Tokens", val))
		}
		handler := func(w http.ResponseWriter, r *http.Request) {

			userValue := r.Context().Value(jwt.ContextUserKey).(models.UserCredentials)

			w.Write([]byte(fmt.Sprintf("Welcome %s!", userValue.Username)))

		}
		r = setValue(r, *creds)

		next := middleware(http.HandlerFunc(handler))
		next.ServeHTTP(w, r)
	}
}

func ValidateTokenBodyHandler(config *conf.Config, userDAO db.UserDAO) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		middleware := jwt.ValidateTokenMiddleware(config, userDAO, "TokensBody")
		//здесь задается рефреш токен
		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		creds := &models.TokenCredentials{
			AccessToken:  data["Access"],
			RefreshToken: data["Refresh"],
		}
		fmt.Println(creds)

		if err != nil {
			errors.MakeInternalServerErrorResponse(&w, "")
			return
		}
		setValue := func(r *http.Request, val models.TokenCredentials) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), "TokensBody", val))
		}
		handler := func(w http.ResponseWriter, r *http.Request) {

			userValue := r.Context().Value(jwt.ContextUserKey).(models.UserCredentials)

			w.Write([]byte(fmt.Sprintf("Welcome %s,%s,%s!", userValue.Username, userValue.RefreshToken, userValue.AccessToken)))

		}
		r = setValue(r, *creds)

		next := middleware(http.HandlerFunc(handler))
		next.ServeHTTP(w, r)
	}
}
