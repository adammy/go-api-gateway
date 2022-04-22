package authentication

import (
	"fmt"
)

type UnauthorizedError struct {
	Message string `json:"message"`
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("unauthorized: %s", e.Message)
}

type ForbiddenError struct {
	Message string `json:"message"`
}

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("forbidden: %s", e.Message)
}
