package auth

import (
	"log"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

const (
	key    = "ZOxgWqggIC56woCU4oTMc54bu8EiZbuHcrmK0bmMZ865egHd52E45eFbhUjCTLy3"
	MaxAge = 86400 * 30
	IsProd = true
)

func NewAuth() {
	if os.Getenv("ENV") != "production" {
		// Load environment variables from .env file
		err := godotenv.Load()
		if err != nil {
			log.Println("No .env file found, using system environment variables.")
		}
	}

	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(MaxAge)

	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = IsProd

	gothic.Store = store

	callbackURL := "https://goth-gracenoble4212-jla4fh1c.leapcell.dev/auth/google/callback"
    log.Printf("Registering OAuth callback URL: %s", callbackURL)

	goth.UseProviders(
		google.New(googleClientId, googleClientSecret, callbackURL),
	)

}
