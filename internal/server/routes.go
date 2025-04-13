package server

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"}, // Add your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true, // Enable cookies/auth
	}))

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	r.GET("/auth/:provider/callback", s.getAuthCallback)

	r.GET("/auth/:provider", s.beginAuthHandler)


	return r
}

func (s *Server) HelloWorldHandler(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.db.Health())
}

func (s *Server) beginAuthHandler(c *gin.Context) {
	provider := c.Param("provider")

	req := c.Request
	q := req.URL.Query()
	q.Add("provider", provider)
	req.URL.RawQuery = q.Encode()

	gothic.BeginAuthHandler(c.Writer, req)
}


func (s *Server) getAuthCallback(c *gin.Context) {
  // 1. grab the provider from the path
  provider := c.Param("provider")

  // 2. inject into the query so gothic can pick it up
  req := c.Request
  q   := req.URL.Query()
  q.Add("provider", provider)
  req.URL.RawQuery = q.Encode()

  // 3. complete the OAuth dance
  user, err := gothic.CompleteUserAuth(c.Writer, req)
  if err != nil {
    // use Gin to write errors
    c.String(http.StatusInternalServerError, "auth error: %v", err)
    return
  }

fmt.Printf("Authenticated user: %+v\n", user)
c.Redirect(http.StatusFound, "http://localhost:3000")
}

