// Package response defines function used to send response to API request
package response

// StatusName represents custom string type for custom status code text
type StatusName string

const (
	// StatusBadRequestCode represents custom status text for HTTP status code 400
	StatusBadRequestCode StatusName = "BAD_REQUEST"
	// StatusUnauthorizedCode represents custom status text for HTTP status code 401
	StatusUnauthorizedCode StatusName = "UNAUTHORIZED"
	// StatusAuthTokenInvalidCode represents custom status text for HTTP status code 401
	StatusAuthTokenInvalidCode StatusName = "INVALID_AUTH_TOKEN"
	// StatusAuthTokenExpiredCode represents custom status text for HTTP status code 401
	StatusAuthTokenExpiredCode StatusName = "AUTH_TOKEN_EXPIRED"
	// StatusMethodNotAllowedCode represents custom status text for HTTP status code 405
	StatusMethodNotAllowedCode StatusName = "METHOD_NOT_ALLOWED"
	// StatusTooManyRequestsCode represents custom status text for HTTP status code 429
	StatusTooManyRequestsCode StatusName = "RATE_LIMIT_EXCEEDED"
	// StatusInternalServerErrorCode represents custom status text for HTTP status code 500
	StatusInternalServerErrorCode StatusName = "INTERNAL_SERVER_ERROR"
	// StatusOKCode StatusName = "OK"
	// StatusCreatedCode             StatusName = "CREATED"
	// StatusForbiddenCode           StatusName = "FORBIDDEN"
	// StatusNotFoundCode            StatusName = "NOT_FOUND"
)

// StatusMessageMap maps status message to respective status name
var StatusMessageMap = map[StatusName]string{
	// StatusOKCode: "OK",
	// StatusCreatedMessage             StatusName = "CREATED"
	// StatusBadRequestMessage          StatusName = "BAD_REQUEST"
	StatusUnauthorizedCode:     "Authentication is required",
	StatusAuthTokenInvalidCode: "Authentication is invalid",
	StatusAuthTokenExpiredCode: "Authentication token has expired. Please log in again",
	// StatusForbiddenMessage           StatusName = "FORBIDDEN"
	// StatusNotFoundMessage            StatusName = "NOT_FOUND"
	StatusMethodNotAllowedCode:    "This HTTP method is not supported for this endpoint",
	StatusTooManyRequestsCode:     "Too many requests. Please try again later",
	StatusInternalServerErrorCode: "An unexpected error occurred",
}

// StatusNameMap maps status code to respective status name
var StatusNameMap = map[StatusName]int{
	// 200: StatusOKCode,
	// 201: StatusCreatedCode,
	// 400: StatusBadRequestCode,
	//
	// 403: StatusForbiddenCode,
	// 404: StatusNotFoundCode,
	// 405: StatusMethodNotAllowedCode,
	// 429: StatusTooManyRequestsCode,
	// 500: StatusInternalServerErrorCode,

	StatusBadRequestCode:          201,
	StatusUnauthorizedCode:        401,
	StatusAuthTokenInvalidCode:    401,
	StatusAuthTokenExpiredCode:    401,
	StatusMethodNotAllowedCode:    405,
	StatusTooManyRequestsCode:     429,
	StatusInternalServerErrorCode: 500,
}

// GetStatusCode returns http status code based on status name
func GetStatusCode(statusName StatusName) int {
	if code, ok := StatusNameMap[statusName]; ok {
		return code
	}
	return 500
}

// GetStatusMessage returns message based on status name
func GetStatusMessage(statusName StatusName) string {
	if message, ok := StatusMessageMap[statusName]; ok {
		return message
	}
	return "An unexpected error occurred"
}
