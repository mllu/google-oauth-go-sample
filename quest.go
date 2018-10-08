package main

import (
	"log"

	"github.com/mllu/google-oauth-go-sample/handlers"
	"github.com/mllu/google-oauth-go-sample/middleware"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

func main() {
	// to change the flags on the default logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	router := gin.Default()
	store := sessions.NewCookieStore([]byte(handlers.RandToken(64)))
	store.Options(sessions.Options{
		Path:   "/",
		MaxAge: 86400 * 7,
	})
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(sessions.Sessions("goquestsession", store))
	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", handlers.IndexHandler)
	router.GET("/login", handlers.LoginHandler)
	router.GET("/callback", handlers.AuthHandler)

	battleAuthorized := router.Group("/battle")
	battleAuthorized.Use(middleware.AuthorizeRequest())
	{
		battleAuthorized.GET("/field", handlers.FieldHandler)
	}

	bucketAuthorized := router.Group("/bucket")
	bucketAuthorized.Use(middleware.AuthorizeRequest())
	{
		bucketAuthorized.GET("/list", handlers.ListBucket)
	}

	router.Run("127.0.0.1:9090")
}
