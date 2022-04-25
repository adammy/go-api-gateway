package filter

import (
	"github.com/gin-gonic/gin"
)

// RunFilter wraps a Filter in a gin.HandlerFunc.
// Execution of the filter is skipped if filter.Active() evaluates to false.
// It next operation, via ctx.Next(), executes in a certain order depending on
// the result of Filter.Type().
func RunFilter(f Filter) gin.HandlerFunc {
	if f.Active() {
		return func(ctx *gin.Context) {
			if f.Type() == Post {
				ctx.Next()
			}

			f.Run(ctx)

			if f.Type() == Pre {
				ctx.Next()
			}
		}

	} else {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}
}
