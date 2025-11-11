// Package main is the entry point for the application
package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// load env vars into application
	_ = godotenv.Load()

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
}

// func main is the first function to be exectued after init()
func main() {
	fmt.Println("Welcome")
	log.Println("Welcome")
}
