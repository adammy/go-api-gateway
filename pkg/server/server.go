package server

import (
	"github.com/gin-gonic/gin"
)

func Run() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"msg": "hello"})
	})
	r.Run()
}
