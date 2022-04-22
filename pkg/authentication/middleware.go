package authentication

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Authentication is middleware TBD.
func Authentication(svc Service) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := ctx.Request.Header.Get("Authorization")
		err := svc.Verify(tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}
		ctx.Next()
	}
}
