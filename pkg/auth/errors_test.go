package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnauthorizedError(t *testing.T) {
	str := "an error"
	err := &UnauthorizedError{
		Err: errors.New(str),
	}
	assert.Error(t, err)
	assert.Equal(t, str, err.Error())
}

func TestForbiddenError(t *testing.T) {
	str := "an error"
	err := &ForbiddenError{
		Err: errors.New(str),
	}
	assert.Error(t, err)
	assert.Equal(t, str, err.Error())
}
