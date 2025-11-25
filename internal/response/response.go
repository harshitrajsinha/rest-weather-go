// Package response defines function used to send response to API request
package response

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/harshitrajsinha/rest-weather-go/internal/models"
)

// SendResponseToClient creates and sends success response to API request
func SendResponseToClient(w http.ResponseWriter, statusCode int, message string, data interface{}) error {

	w.Header().Set("Content-Type", "application/json")
	response := models.Response{
		Code:    http.StatusText(statusCode),
		Message: message,
		Data:    data,
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(response); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred", "error": {}}`))
		return err
	}

	w.WriteHeader(statusCode)
	b.WriteTo(w)

	return nil
}

// SendErrorResponseToClient creates and sends error response to API request
func SendErrorResponseToClient(w http.ResponseWriter, statusName StatusName, errorDetails map[string]string) error {

	w.Header().Set("Content-Type", "application/json")
	errorResponse := models.ErrorResponse{
		Code:    string(statusName),
		Message: GetStatusMessage(statusName),
		Error:   errorDetails,
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(errorResponse); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred", "error": {}}`))
		return err
	}

	w.WriteHeader(GetStatusCode(statusName))
	b.WriteTo(w)

	return nil
}
