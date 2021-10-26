package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	logging "auth_service/pkg/logging"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const PORT string = ":8080"

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	logEntry := logrus.NewEntry(log)
	config := conf.New()
	userDAO := db.InMemroyUserDAO{}

	r := mux.NewRouter()

	fmt.Println("Server started...")

	r.Handle("/login", auth.SignInHandler(config, &userDAO)).Methods("POST")
	r.Handle("/logout", auth.SignOutHandler(config))
	r.Handle("/hello", http.HandlerFunc(auth.Hello))
	r.Handle("/i", auth.ValidateTokenHeadersHandler(config, &userDAO))
	r.Handle("/me", auth.ValidateTokensInBodyHandler(config, &userDAO))

	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	handler := logging.LoggingMiddleware(logEntry)(r)
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
