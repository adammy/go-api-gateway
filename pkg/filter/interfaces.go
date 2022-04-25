package filter

import (
	"github.com/gin-gonic/gin"
)

// Filter defines the contract for a process that can run before
// proxying a request.
type Filter interface {
	Active() bool
	Type() FilterType
	Order() int
	Run(ctx *gin.Context)
}
