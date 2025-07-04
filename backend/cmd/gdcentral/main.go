package main

import (
	"log"
	"os"

	"crypto/tls"
	"net/http"

	"github.com/Aproxia-dev/gd-central/backend/internal/api"
	"github.com/Aproxia-dev/gd-central/backend/internal/db"
	"github.com/Aproxia-dev/gd-central/backend/internal/oauth"

	"github.com/gofiber/fiber/v2"
)

func main() {
	if os.Getenv("APP_ENV") == "dev" {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	err := db.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	oauth.GetProviders()
	app := fiber.New()
	api.RegisterRoutes(app)
	app.Listen(":8000")
}
