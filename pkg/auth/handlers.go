package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
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

func makeUnauthorisedResponse(w *http.ResponseWriter) {
	(*w).Header().Set("WWW-Authenticate", "Basic realm=auth")
	(*w).WriteHeader(401)
	(*w).Write([]byte("Unauthorised.\n"))
}

func makeInternalServerErrorResponse(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusInternalServerError)
}
func makeBadRequestResponse(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusBadRequest)
}

// Контроллер логина, конфиг инжектится
func SignInHandler(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds Credentials
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			//
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		username := creds.Username
		password := creds.Password

		userDAO := db.InMemroyUserDAO{}
		ok := checkUserPassowrd(username, password, &userDAO, config)

		if !ok {
			makeUnauthorisedResponse(&w)
			return
		}

		accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, password, config.SecretKeyAccess)

		if err != nil {
			fmt.Println(accessToken, err)
			makeInternalServerErrorResponse(&w)
		}

		refreshToken, refreshExpirationTime, err := jwt.CreateRefreshToken(username, password, config.SecretKeyRefresh)
		if err != nil {
			fmt.Println(refreshToken, err)
			makeInternalServerErrorResponse(&w)
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
func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Println("hello")
}

// Тестовая ручка чтоб посмотреть в хедеры и заюзать мидлварь
func Test(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("MIDDLEWARE!")
		next := CheckRefreshToken(hello, config)
		next.ServeHTTP(w, r)
	}
}
