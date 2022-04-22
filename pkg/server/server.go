package server

import (
	"log"
	"net/http"

	"github.com/SpotOnInc/go-api-gateway/pkg/authentication"
	"github.com/gin-gonic/gin"
)

// Run TBD.
func Run() {

	authSvc := authentication.NewService("https://id.adammy.com/oauth2/default/v1/keys")
	_ = authSvc.SetPublicKeys()

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(authentication.Authentication(authSvc))
	r.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"msg": "hello"})
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal("can't start server: %w", err)
	}
}
