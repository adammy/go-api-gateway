package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

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
		log.Info().Msg("err")
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

func ping(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"msg": "hello"})
}

func proxy(ctx *gin.Context) {
	remote, _ := url.Parse("https://jsonplaceholder.typicode.com/posts")
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = func(req *http.Request) {
		req.Header = ctx.Request.Header
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.URL.Path = ctx.Param("proxyPath")
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}
