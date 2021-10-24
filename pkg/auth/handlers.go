package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/errors"
	"auth_service/pkg/jwt"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

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
			errors.MakeUnathorisedErrorResponse(&w)
			return
		}

		accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, password, config.SecretKeyAccess)

		if err != nil {
			fmt.Println(accessToken, err)
			errors.MakeInternalServerErrorResponse(&w)
		}

		refreshToken, refreshExpirationTime, err := jwt.CreateRefreshToken(username, password, config.SecretKeyRefresh)
		if err != nil {
			fmt.Println(refreshToken, err)
			errors.MakeInternalServerErrorResponse(&w)
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

func ValidateTokenHeadersHandler(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		middleware := jwt.ValidateTokenMiddleware(config)
		handler := func(w http.ResponseWriter, r *http.Request) {
			userValue := r.Context().Value(jwt.ContextUserKey)
			fmt.Println(userValue)
			w.Write([]byte("hello"))
		}
		next := middleware(http.HandlerFunc(handler))
		next.ServeHTTP(w, r)
	}
}
