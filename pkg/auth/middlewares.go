package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/jwt"
	"fmt"
	"net/http"
	"reflect"
)

// мидлварь чтобы чекать живость refresh токена,
// по возможности обновлять пару (access, refresh) или отправлять на /login
func CheckRefreshToken(next http.HandlerFunc, config *conf.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//fmt.Println("Access: ", r.Cookie("Access"))
		//fmt.Println("Refresh: ", r.Header.Get("Refresh"))

		accessCookie, err := r.Cookie("Access")
		if err != nil {
			if err == http.ErrNoCookie {

				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accessToken := accessCookie.Value
		refreshCookie, err := r.Cookie("Refresh")
		if err != nil {
			if err == http.ErrNoCookie {

				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			return
		}
		refreshToken := refreshCookie.Value
		ok1, err1, username := jwt.TokenIsExpired(accessToken, config.SecretKeyAccess, false)
		if err1 != nil {
			makeInternalServerErrorResponse(&w)

		}

		ok2, err2, _ := jwt.TokenIsExpired(refreshToken, config.SecretKeyRefresh, true)
		if err2 != nil {
			makeInternalServerErrorResponse(&w)
		}
		if !ok1 && !ok2 {
			w.Write([]byte("keeep going"))
			//http.Redirect(w,r,"http://localhost:8080/i",200)
		} else if ok2 {
			http.Redirect(w, r, "http://localhost:8080/logout", 200)
		}
		if ok1 {
			password := db.Users[username].Password
			accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, password, config.SecretKeyAccess)
			if err != nil {

			}
			http.SetCookie(w, &http.Cookie{
				Name:    "Token",
				Value:   accessToken,
				Path:    "/",
				Expires: accessExpirationTime,
			})
		}

		fmt.Println(ok1, ok2, reflect.TypeOf(err1), reflect.TypeOf(err2), err1, err2)
		next.ServeHTTP(w, r)
	})
}
