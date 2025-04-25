// In a new file: internal/auth/middleware.go
package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func JWTAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }
        
        // Extract the token from the Authorization header
        // Format should be "Bearer {token}"
        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
            c.Abort()
            return
        }
        
        // Parse and validate the token
        token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
            // Validate signing method
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return JWTSecret, nil
        })
        
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            c.Abort()
            return
        }
        
        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            // Store claims in context for handlers to use
            c.Set("userID", claims["id"])
            c.Set("userEmail", claims["email"])
            c.Set("userName", claims["name"])
            c.Set("userAvatar", claims["avatar"])
            c.Set("userProvider", claims["provider"])
            c.Next()
        } else {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
    }
}