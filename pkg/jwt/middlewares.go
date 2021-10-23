package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"auth_service/pkg/conf"
	"auth_service/pkg/models"

	"github.com/golang-jwt/jwt"
)

type ErrorMsg struct {
	Message string `json:"message"`
}

type UserKey string

var userKey UserKey = "user"

// TODO: Access user through user interface + pass user data in ctx <23-10-21, ddbelyaev> //
// This is a JWT validating middleware. It's purpose is to validate JWT before allowing users
// request to fall through to next middleware. As a result, it passes on user info in context (ctx).
func ValidateTokenMiddleware(config *conf.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authorizationHeader := req.Header.Get("Access")
			refreshHeader := req.Header.Get("Refresh")

			if authorizationHeader != "" {
				bearerToken := strings.Split(authorizationHeader, " ")
				if len(bearerToken) == 2 {
					claims := &Claims{}
					token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
							return nil, fmt.Errorf("There was an error")
						}
						return []byte(config.SecretKeyAccess), nil
					})

					if err != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}

					if token.Valid {
						var userCreds models.UserCredentials

						userCreds.Username = claims.Username
						userCreds.AccessToken = authorizationHeader
						userCreds.RefreshToken = refreshHeader

						ctx := context.WithValue(req.Context(), userKey, userCreds)
						next.ServeHTTP(w, req.WithContext(ctx))
					} else {
						json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnauthorized)
					}
				} else {
					json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
				}
			} else {
				json.NewEncoder(w).Encode(ErrorMsg{Message: "An authorization header is required"})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
			}
		})
	}
}
