package server

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := gin.Default()

	allowedOrigins := []string{"http://localhost:3000"}
	if os.Getenv("ENV") == "production" {
		// Add production frontend URL
		allowedOrigins = append(allowedOrigins, "https://goth-frontend.vercel.app")
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true, // Enable cookies/auth
		ExposeHeaders:    []string{"Content-Length"},
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	r.GET("/auth/:provider/callback", s.getAuthCallback)

	r.GET("/auth/:provider", s.beginAuthHandler)

	r.GET("/api/me", s.getCurrentUser)

	r.GET("/auth/logout", s.logoutHandler)

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
	q := req.URL.Query()
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
	c.Redirect(http.StatusFound, "https://goth-frontend.vercel.app/auth/callback")
}

func (s *Server) getCurrentUser(c *gin.Context) {
    user, err := gothic.CompleteUserAuth(c.Writer, c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "id": user.UserID,
        "name": user.Name,
        "email": user.Email,
        "avatar": user.AvatarURL,
        "provider": user.Provider,
    })
}

func (s *Server) logoutHandler(c *gin.Context) {
    gothic.Logout(c.Writer, c.Request)
    c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}