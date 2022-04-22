package authentication

import (
	"fmt"
)

type UnauthorizedError struct {
	message string
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("unauthorized: %s", e.message)
}

type ForbiddenError struct {
	message string
}

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("forbidden: %s", e.message)
}
