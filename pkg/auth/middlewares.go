package auth

import (
	"fmt"
	"net/http"
)

func CheckRefreshToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Access: ", r.Header.Get("Access"))
		fmt.Println("Refresh: ", r.Header.Get("Refresh"))

		next.ServeHTTP(w, r)
	})
}
