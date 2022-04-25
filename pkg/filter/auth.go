package filter

import (
	"net/http"

	"github.com/SpotOnInc/go-api-gateway/pkg/auth"
	"github.com/gin-gonic/gin"
)

var _ Filter = (*AuthFilter)(nil)

// AuthFilter runs logic for validating auth and aborting the request
// if an incoming JWt is invalid.
type AuthFilter struct {
	svc auth.Service
}

// NewAuthFilter creates an AuthFilter.
func NewAuthFilter(svc auth.Service) *AuthFilter {
	return &AuthFilter{
		svc: svc,
	}
}

// Active determines if the AuthFilter's Run method should be utilized.
func (f *AuthFilter) Active() bool {
	return true
}

// Type for AuthFilter should be Pre.
func (f *AuthFilter) Type() FilterType {
	return Pre
}

// Order determines the priority of this Filter.
func (f *AuthFilter) Order() int {
	return 1
}

// Run validates if the incoming JWT is valid.
func (f *AuthFilter) Run(ctx *gin.Context) {
	tokenString := ctx.Request.Header.Get("Authorization")
	err := f.svc.Verify(tokenString)
	if err != nil {
		switch err.(type) {
		case *auth.UnauthorizedError:
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, NewGatewayError(http.StatusUnauthorized, "Unauthorized", err.Error(), ctx))
		case *auth.ForbiddenError:
			ctx.AbortWithStatusJSON(http.StatusForbidden, NewGatewayError(http.StatusForbidden, "Forbidden", err.Error(), ctx))
		default:
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, NewGatewayError(http.StatusInternalServerError, "Internal Server Error", err.Error(), ctx))
		}
		return
	}
}
