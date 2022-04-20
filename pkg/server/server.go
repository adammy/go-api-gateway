package server

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Run TBD.
func Run() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"msg": "hello"})
	})

	if err := r.Run(); err != nil {
		log.Fatal("can't start server: %w", err)
	}
}
