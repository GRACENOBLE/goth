// Create a new file: internal/auth/jwt.go
package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/markbates/goth"
)

var JWTSecret []byte

func init() {
    secret := os.Getenv("JWT_SECRET_KEY")
    if secret == "" {
        panic("JWT_SECRET_KEY environment variable is not set")
    }
    JWTSecret = []byte(secret)
}

func GenerateJWT(user goth.User) (string, error) {
    // Create a new token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "id":       user.UserID,
        "email":    user.Email,
        "name":     user.Name,
        "avatar":   user.AvatarURL,
        "provider": user.Provider,
        "exp":      time.Now().Add(time.Hour * 24 * 7).Unix(), // 1 week
    })
    
    // Sign and get the complete encoded token as a string
    return token.SignedString(JWTSecret)
}