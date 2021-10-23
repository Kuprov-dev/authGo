package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"auth_service/models"

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
func ValidateTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Cookie("Access") //Header.Get("authorization")
		refreshHeader := req.Cookie("Refresh") //Header.Get("authorization")

		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				// token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
				// 	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				// 		return nil, fmt.Errorf("There was an error")
				// 	}
				// 	return []byte("secret"), nil
				// })

				claims := &Claims{}
				token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte(secretKey), nil
				})

				if error != nil {
					json.NewEncoder(w).Encode(ErrorMsg{Message: error.Error()})
					return
				}

				if token.Valid {
					var userCreds models.UserCredentials

					userCreds.Username = claims.Username
					userCreds.AccessToken = authorizationHeader
					userCreds.RefreshToken = refreshHeader

					ctx := context.WithValue(r.Context(), userKey, userCreds)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
				}
			} else {
				json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
			}
		} else {
			json.NewEncoder(w).Encode(ErrorMsg{Message: "An authorization header is required"})
		}
	})
}
