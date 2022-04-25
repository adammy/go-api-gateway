package auth

// UnauthorizedError denotes the user is unauthorized.
type UnauthorizedError struct {
	Err error
}

func (e *UnauthorizedError) Error() string {
	return e.Err.Error()
}

// ForbiddenError denotes the user is forbidden from accessing a resource.
type ForbiddenError struct {
	Err error
}

func (e *ForbiddenError) Error() string {
	return e.Err.Error()
}
