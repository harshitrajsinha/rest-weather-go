// Package models defines structures used across the application
package models

// Response defines structure for the API response that will be send for a request
type Response struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ErrorResponse defines structure for the error response that will be send for a request
type ErrorResponse struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Error   map[string]string `json:"error"`
}
