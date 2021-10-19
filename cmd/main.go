package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := conf.New()

	PORT := ":8080"

	mux := http.NewServeMux()
	s := &http.Server{
		Addr:         PORT,
		Handler:      mux,
		IdleTimeout:  10 * time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	defer s.Close()

	fmt.Println("Server started...")

	mux.Handle("/login", auth.SignInHandler(config))
	mux.Handle("/logout", auth.SignOutHandler(config))
	mux.Handle("/test", http.HandlerFunc(auth.Test))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println(err)
			return
		}
	}()

	<-stop

	fmt.Println("Server stopped...")
}
