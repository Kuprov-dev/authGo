package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := conf.New()

	PORT := ":8080"

	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(file)

	mux := http.NewServeMux()

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

	handler := auth.Logging(mux)
	s := &http.Server{
		Addr:         PORT,
		Handler:      handler,
		IdleTimeout:  10 * time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	defer s.Close()

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println(err)
			return
		}
	}()

	<-stop

	fmt.Println("Server stopped...")
}
