package filter

import (
	"time"

	"github.com/gin-gonic/gin"
)

type GatewayError struct {
	Status    int    `json:"status"`
	Subject   string `json:"error"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	Path      string `json:"path"`
}

func (e *GatewayError) Error() string {
	return e.Subject
}

func NewGatewayError(status int, subject, message string, ctx *gin.Context) *GatewayError {
	return &GatewayError{
		Status:    status,
		Subject:   subject,
		Message:   message,
		Timestamp: time.Now().Format("2006-01-02T15:04:05-0700"),
		Path:      ctx.Request.URL.Path,
	}
}
