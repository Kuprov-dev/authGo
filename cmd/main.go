package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	logging "auth_service/pkg/logging"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

const PORT string = ":8080"

func main() {
	config := conf.New()

	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	logEntry := logrus.NewEntry(log)

	mux := http.NewServeMux()

	fmt.Println("Server started...")

	mux.Handle("/login", auth.SignInHandler(config))
	mux.Handle("/logout", auth.SignOutHandler(config))
	mux.Handle("/hello", http.HandlerFunc(auth.Hello))
	mux.Handle("/me", auth.ValidateTokenHandler(config))

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	handler := logging.LoggingMiddleware(logEntry)(mux)
	s := &http.Server{
		Addr:    PORT,
		Handler: handler,

		// So because the WriteTimeout was set pprof yielded an error,
		// that is why, and due to redundancy, setting timeouts was commented
		// IdleTimeout:  10 * time.Second,
		// ReadTimeout:  time.Second,
		// WriteTimeout: time.Second,
	}
	defer s.Close()

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println(err)
			return
		}
	}()

	<-stop

	fmt.Println("Server stopped...")
}
