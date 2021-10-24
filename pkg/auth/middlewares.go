package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/errors"
	"auth_service/pkg/jwt"
	"auth_service/pkg/models"
	"context"
	"net/http"
)

// мидлварь чтобы чекать живость refresh токена,
// по возможности обновлять пару (access, refresh) или отправлять на /login
func CheckRefreshToken(next http.HandlerFunc, config *conf.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			errors.MakeInternalServerErrorResponse(&w, "")
		}

		ok2, err2, _ := jwt.TokenIsExpired(refreshToken, config.SecretKeyRefresh, true)
		if err2 != nil {
			errors.MakeInternalServerErrorResponse(&w, "")
		}
		if !ok1 && !ok2 {
			w.Write([]byte("keeep going"))
		} else if ok2 {
			http.Redirect(w, r, "http://localhost:8080/logout", 200)
		}
		if ok1 {
			accessToken, accessExpirationTime, err := jwt.CreateAccessToken(username, config.SecretKeyAccess)
			if err != nil {

			}
			http.SetCookie(w, &http.Cookie{
				Name:    "Token",
				Value:   accessToken,
				Path:    "/",
				Expires: accessExpirationTime,
			})
		}

		next.ServeHTTP(w, r)
	})
}

type ContextKey string

var ContextTokenCredsKey ContextKey = "tokenCreds"

// Тестовая мидлварь которая берет из хедера и кладет в контекст
func GetFromHeadersAndPassToContext(config *conf.Config, userDao db.UserDAO) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			creds := &models.TokenCredentials{
				AccessToken:  r.Header.Get("Access"),
				RefreshToken: r.Header.Get("Refresh"),
			}
			ctx := context.WithValue(r.Context(), ContextTokenCredsKey, creds)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
