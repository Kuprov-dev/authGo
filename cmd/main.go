package main

import (
	"auth_service/pkg/auth"
	"auth_service/pkg/conf"
	"auth_service/pkg/db"
	logging "auth_service/pkg/logging"
	"auth_service/pkg/prometheusMiddleware"
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

const PORT string = ":8081"

var connectionString = "mongodb://localhost:27017/"

func main() {
	config := conf.New()
	db.ConnectMongoDB(context.TODO(), config)
	userDBDAO := db.NewMongoDBTemp(context.TODO(), db.GetMongoDBConnection())

	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	logEntry := logrus.NewEntry(log)

	userDAO := db.InMemroyUserDAO{}

	r := mux.NewRouter()

	fmt.Println("Server started...")
	metricsMiddleware := prometheusMiddleware.NewMetricsMiddleware()
	r.Handle("/login", auth.SignInHandler(config, &userDAO, context.TODO(), userDBDAO)).Methods("POST")
	r.Handle("/logout", auth.SignOutHandler(config))
	r.Handle("/hello", http.HandlerFunc(auth.Hello))
	r.Handle("/i", auth.ValidateTokenHeadersHandler(config, &userDAO))
	r.Handle("/me", auth.ValidateTokensInBodyHandler(config, &userDAO))
	r.Handle("/metrics", promhttp.Handler())
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)

	r.Use(metricsMiddleware.Metrics)
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

		}
	}()

	<-stop

	fmt.Println("Server stopped...")
}
