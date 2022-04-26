package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

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
