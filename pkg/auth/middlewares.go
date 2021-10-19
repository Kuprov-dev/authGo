package auth

import (
	"auth_service/pkg/conf"
	"auth_service/pkg/jwt"
	"fmt"
	"net/http"
	"reflect"
)

// мидлварь чтобы чекать живость refresh токена,
// по возможности обновлять пару (access, refresh) или отправлять на /login
func CheckRefreshToken(next http.HandlerFunc, config *conf.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Access: ", r.Header.Get("Access"))
		fmt.Println("Refresh: ", r.Header.Get("Refresh"))

		accessToken := r.Header.Get("Access")
		refreshToken := r.Header.Get("Refresh")

		ok1, err1 := jwt.TokenIsExpired(accessToken, config.SecretKeyAccess)
		// if err1 != nil {
		// 	makeInternalServerErrorResponse(&w)
		// }

		ok2, err2 := jwt.TokenIsExpired(refreshToken, config.SecretKeyRefresh)
		// if err2 != nil {
		// 	makeInternalServerErrorResponse(&w)
		// }

		fmt.Println(ok1, ok2, reflect.TypeOf(err1), reflect.TypeOf(err2), err1, err2)
		next.ServeHTTP(w, r)
	})
}
