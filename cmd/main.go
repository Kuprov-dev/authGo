package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	"fmt"
	"log"
	"net/http"
)

func main() {
	config := conf.New()

	http.HandleFunc("/login", auth.SignInHandler(config))
	http.HandleFunc("/logout", auth.SignOutHandler(config))
	http.HandleFunc("/test", auth.Test(config))

	fmt.Println("Starting server")
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}
