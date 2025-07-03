package main

import (
	"github.com/Aproxia-dev/gd-central/backend/internal/api"
	"github.com/Aproxia-dev/gd-central/backend/internal/oauth"

	"github.com/gofiber/fiber/v2"
)

func main() {
	oauth.GetProviders()
	app := fiber.New()
	api.RegisterRoutes(app)
	app.Listen(":8000")
}
