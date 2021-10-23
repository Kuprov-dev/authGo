package log

import (
	"context"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type loggerCtxKey struct{}

func LoggingMiddleware(log *logrus.Entry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			newEntry := log.WithFields(logrus.Fields{
				"method": r.Method,
				"path":   r.URL.Path,
				"time":   time.Now(),
			})

			newEntry.Info("kek")

			ctx := context.WithValue(r.Context(), loggerCtxKey{}, newEntry)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
