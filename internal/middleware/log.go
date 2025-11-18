// Package middleware adds additional functionality of log, authentication around request-response cycle
package middleware

import (
	"log"
	"net/http"
	"time"
)

// CustomResponseWriter embeds http.ResponseWriter to override WriteHeader()
type CustomResponseWriter struct {
	Code int
	http.ResponseWriter
}

// WriteHeader overrides built-in WriteHeader to capture status code
func (crw *CustomResponseWriter) WriteHeader(statusCode int) {
	crw.Code = statusCode
	crw.ResponseWriter.WriteHeader(statusCode)
}

// LogMiddleware logs request and response
func LogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		startTime := time.Now()

		// set default values for ResponseWriter in case it is not invoked
		crw := &CustomResponseWriter{
			Code:           200,
			ResponseWriter: w,
		}

		next.ServeHTTP(crw, r)

		elapsedTime := time.Since(startTime).Round(time.Minute)
		code := crw.Code
		level := "[INFO]"
		if code >= 400 {
			level = "[ERROR]"
		}

		log.Printf("%s %s %s %d %v", level, r.Method, r.URL.Path, code, elapsedTime)

	})
}
