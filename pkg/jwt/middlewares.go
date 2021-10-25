package jwt

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	"auth_service/pkg/errors"
	"auth_service/pkg/models"
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
)

type ContextKey string

var ContextUserKey ContextKey = "tokenCreds"
var ContextUserBody ContextKey = "TokensBody"

// TODO: Access user through user interface + pass user data in ctx <23-10-21, ddbelyaev> //
// This is a JWT validating middleware. It's purpose is to validate JWT before allowing users
// request to fall through to next middleware. As a result, it passes on user info in context (ctx).
func ValidateTokenMiddleware(config *conf.Config, userDAO db.UserDAO, con string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// вот так передается токен по контексту
			var tokenCreds models.TokenCredentials
			if con == "TokensBody" {
				tokenCreds = req.Context().Value(con).(models.TokenCredentials)
			} else {
				tokenCreds = req.Context().Value("Tokens").(models.TokenCredentials)
			}
			//if !ok {
			//	errors.MakeUnathorisedErrorResponse(&w, "Empty token creds in context.")
			//	return
			//}
			fmt.Println(tokenCreds)

			accessToken := tokenCreds.AccessToken
			refreshToken := tokenCreds.RefreshToken

			if accessToken == "" {
				errors.MakeUnathorisedErrorResponse(&w, "An authorization header is required.")
				return
			}

			bearerToken := [2]string{accessToken, refreshToken}

			if len(bearerToken) != 2 {
				errors.MakeUnathorisedErrorResponse(&w, "Invalid authorization token.")
				return
			}

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(config.SecretKeyRefresh), nil
			})

			if !token.Valid {
				ve, ok := err.(*jwt.ValidationError)
				if !ok {
					errors.MakeBadRequestErrorResponse(&w, "")
					return
				}

				switch {
				case ve.Errors&jwt.ValidationErrorMalformed != 0:
					errors.MakeUnathorisedErrorResponse(&w, "Token is not valid JWT.")
					return
				case ve.Errors&jwt.ValidationErrorExpired != 0:
					if refreshedTokenCreds, err := RefreshTokens(claims.Username, refreshToken, config, userDAO); err != nil {
						errors.MakeUnathorisedErrorResponse(&w, err.Error())
						return
					} else {
						refreshTokenHeaders(&w, refreshedTokenCreds)
					}

				case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
					errors.MakeUnathorisedErrorResponse(&w, "Token is not valid yet.")
					return
				default:
					errors.MakeUnathorisedErrorResponse(&w, "Unhandled error when JWT parsing.")
					return
				}
			}
			claims = &Claims{}
			token, err = jwt.ParseWithClaims(bearerToken[0], claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(config.SecretKeyAccess), nil
			})
			if !token.Valid {
				ve, ok := err.(*jwt.ValidationError)
				if !ok {
					errors.MakeBadRequestErrorResponse(&w, "")
					return
				}

				switch {
				case ve.Errors&jwt.ValidationErrorMalformed != 0:
					errors.MakeUnathorisedErrorResponse(&w, "Token is not valid JWT.")
					return
				case ve.Errors&jwt.ValidationErrorExpired != 0:
					accessToken, _, err = CreateAccessToken(claims.Username, config.SecretKeyAccess)
					if err != nil {
						errors.MakeBadRequestErrorResponse(&w, "")
						return
					}

				case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
					errors.MakeUnathorisedErrorResponse(&w, "Token is not valid yet.")
					return
				default:
					errors.MakeUnathorisedErrorResponse(&w, "Unhandled error when JWT parsing.")
					return
				}
			}
			userCreds := models.UserCredentials{
				Username:     claims.Username,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			}
			ctx := context.WithValue(req.Context(), ContextUserKey, userCreds)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}
