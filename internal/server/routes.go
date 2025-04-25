package server

import (
	"fmt"
	"goth/internal/auth"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
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
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "Origin"},
		AllowCredentials: true, // Enable cookies/auth
		ExposeHeaders:    []string{"Content-Length"},
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	r.GET("/auth/:provider/callback", s.getAuthCallback)

	r.GET("/auth/:provider", s.beginAuthHandler)
	// Add new JWT-based endpoint
	r.GET("/api/user", s.getUserFromJWT)

	// Keep the old endpoint for backward compatibility
	r.GET("/api/me", s.getCurrentUser)

	r.GET("/auth/logout", s.logoutHandler)

	return r
}

func (s *Server) getUserFromJWT(c *gin.Context) {
    // Extract the token from the Authorization header
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
        return
    }
    
    // Split the header
    parts := strings.SplitN(authHeader, " ", 2)
    if len(parts) != 2 || parts[0] != "Bearer" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
        return
    }
    
    // Parse the token
    token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return auth.JWTSecret, nil
    })
    
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        c.JSON(http.StatusOK, gin.H{
            "id":       claims["id"],
            "email":    claims["email"],
            "name":     claims["name"],
            "avatar":   claims["avatar"],
            "provider": claims["provider"],
        })
    } else {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
    }
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
	token, err := auth.GenerateJWT(user)
	if err != nil {
		c.Redirect(http.StatusFound, "https://your-vercel-app.vercel.app/auth/callback?token="+token)
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
		"id":       user.UserID,
		"name":     user.Name,
		"email":    user.Email,
		"avatar":   user.AvatarURL,
		"provider": user.Provider,
	})
}

func (s *Server) logoutHandler(c *gin.Context) {
	gothic.Logout(c.Writer, c.Request)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
