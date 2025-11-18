// Package main is the entry point for the application
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/harshitrajsinha/rest-weather-go/internal/config"
	"github.com/harshitrajsinha/rest-weather-go/internal/database"
	"github.com/harshitrajsinha/rest-weather-go/internal/handler"
	"github.com/harshitrajsinha/rest-weather-go/internal/middleware"
)

var dbClient *database.DBClient
var cfg *config.Config

func init() {
	var err error
	// load env vars into application
	_ = godotenv.Load()

	cfg, err = config.Load()
	if err != nil {
		log.Fatalln(err)
	}

	// set log flags for UTC timezone and file identification
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)

	// set log rotation and output path
	log.SetOutput(&lumberjack.Logger{
		Filename:   "logs/app.log",
		MaxAge:     28,
		MaxSize:    5,
		MaxBackups: 3,
		Compress:   true,
	})

	// load database client
	dbClient, err = database.InitDB()
	if err != nil {
		log.Fatalln(err)
	}
	if err = dbClient.LoadDataToDatabase(); err != nil {
		log.Fatalln(err)
	}
}

// main is the first function to be exectued after init()
func main() {

	defer dbClient.Close()

	loginHandler := handler.NewLoginHandler(dbClient, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.SecretAuthKey)

	// local mux server
	mux := http.NewServeMux()

	// setup routes

	mux.Handle("GET /health", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := dbClient.HealthCheck(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`message:"Application is not functioning"`))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`message:"Application is functioning"`))
	}), cfg.SecretAuthKey))

	mux.HandleFunc("GET /login", loginHandler.HandleGoogleLogin)
	// mux.HandleFunc("GET /logout", loginHandler.HandleGoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", loginHandler.HandleGoogleCallback)

	muxWithLog := middleware.LogMiddleware(mux)

	// set server settings
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      muxWithLog,
		ReadTimeout:  8 * time.Second,
		WriteTimeout: 8 * time.Second,
		IdleTimeout:  8 * time.Second,
	}

	// start server asynchronously
	go func() {
		log.Println("starting server at port: ", cfg.Port)
		fmt.Println("starting server at port: ", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("error starting server, %v", err)
		}
	}()

	// gracefull server shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("attempt for gracefull shutdown")

	ctxWithContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if err := server.Shutdown(ctxWithContext); err != nil {
		log.Fatalf("error shutting down server gracefully, %v", err)
	}
	fmt.Println("server closed")
	log.Println("server closed")
}
