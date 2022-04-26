package server

import (
	"github.com/SpotOnInc/go-api-gateway/pkg/auth"
	"github.com/SpotOnInc/go-api-gateway/pkg/filter"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// Run will start the HTTP server for the API Gateway application.
func Run() {
	authSvc := auth.NewService("https://id.adammy.com/oauth2/default/v1/keys")
	err := authSvc.SetPublicKeys()
	if err != nil {
		log.Err(err).Msg("unable to set public keys for auth service")
	}

	authFilter := filter.NewAuthFilter(authSvc)

	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.GET("/ping", ping)
	r.Any("/proxy/*proxyPath", filter.RunFilter(authFilter), proxy)

	if err := r.Run(":8080"); err != nil {
		log.Fatal().Err(err).Msg("can't start the server")
	}
}
