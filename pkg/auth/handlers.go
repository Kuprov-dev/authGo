package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/jwt"
	"fmt"
	"net/http"
	"time"
)

func makeUnauthorisedResponse(w *http.ResponseWriter) {
	(*w).Header().Set("WWW-Authenticate", "Basic realm=auth")
	(*w).WriteHeader(401)
	(*w).Write([]byte("Unauthorised.\n"))
}

func makeInternalServerErrorResponse(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusInternalServerError)
}

func SignInHandler(config *conf.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()

		userDAO := db.InMemroyUserDAO{}
		ok := checkUserPassowrd(username, password, &userDAO)

		if !ok {
			makeUnauthorisedResponse(&w)
			return
		}

		accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, password, config)

		if err != nil {
			fmt.Println(accessToken, err)
			makeInternalServerErrorResponse(&w)
		}

		refreshToken, refreshExpirationTime, err := jwt.CreateRefreshToken(username, password, config)
		if err != nil {
			fmt.Println(refreshToken, err)
			makeInternalServerErrorResponse(&w)
		}

		userDAO.UpdateRefreshToken(username, refreshToken)

		http.SetCookie(w, &http.Cookie{
			Name:    "Token",
			Value:   accessToken,
			Expires: accessExpirationTime,
		})

		http.SetCookie(w, &http.Cookie{
			Name:    "Refresh",
			Value:   refreshToken,
			Expires: refreshExpirationTime,
		})

	}
}

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

func hello(w http.ResponseWriter, r *http.Request) {
	// Тестовый хендлер чтоб посмотреть в хедеры
	fmt.Println("hello")
}

func Test(w http.ResponseWriter, r *http.Request) {
	// Тестовая ручка чтоб посмотреть в хедеры и заюзать мидлварь
	fmt.Println("MIDDLEWARE!")
	next := CheckRefreshToken(hello)
	next.ServeHTTP(w, r)
}
